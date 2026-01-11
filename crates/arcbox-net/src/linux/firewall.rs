//! Linux firewall rule management (iptables/nftables).
//!
//! This module provides functionality for managing firewall rules for NAT,
//! port forwarding, and traffic filtering. Supports both iptables (legacy)
//! and nftables (modern) backends.

use std::net::Ipv4Addr;
use std::process::Command;

use ipnetwork::Ipv4Network;

use crate::error::{NetError, Result};

/// Chain name prefix for ArcBox rules.
const CHAIN_PREFIX: &str = "ARCBOX";

/// Firewall backend type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FirewallBackend {
    /// Use iptables (legacy).
    #[default]
    Iptables,
    /// Use nftables (modern).
    Nftables,
}

impl FirewallBackend {
    /// Detects the available firewall backend.
    ///
    /// Prefers nftables if available, falls back to iptables.
    pub fn detect() -> Self {
        // Check for nft command
        if Command::new("nft").arg("--version").output().is_ok() {
            return Self::Nftables;
        }

        // Fall back to iptables
        Self::Iptables
    }
}

/// Network protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// TCP protocol.
    Tcp,
    /// UDP protocol.
    Udp,
    /// Both TCP and UDP.
    Both,
}

impl Protocol {
    /// Returns the protocol name for iptables/nftables.
    fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Both => "all",
        }
    }
}

/// NAT type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// MASQUERADE (dynamic source NAT).
    Masquerade,
    /// SNAT (static source NAT).
    Snat,
}

/// NAT rule configuration.
#[derive(Debug, Clone)]
pub struct NatRule {
    /// Source network (internal).
    pub source: Ipv4Network,
    /// Output interface (external).
    pub out_interface: String,
    /// NAT type.
    pub nat_type: NatType,
    /// SNAT target address (if nat_type is Snat).
    pub snat_addr: Option<Ipv4Addr>,
}

impl NatRule {
    /// Creates a new MASQUERADE NAT rule.
    #[must_use]
    pub fn masquerade(source: Ipv4Network, out_interface: impl Into<String>) -> Self {
        Self {
            source,
            out_interface: out_interface.into(),
            nat_type: NatType::Masquerade,
            snat_addr: None,
        }
    }

    /// Creates a new SNAT rule.
    #[must_use]
    pub fn snat(
        source: Ipv4Network,
        out_interface: impl Into<String>,
        snat_addr: Ipv4Addr,
    ) -> Self {
        Self {
            source,
            out_interface: out_interface.into(),
            nat_type: NatType::Snat,
            snat_addr: Some(snat_addr),
        }
    }
}

/// Port forwarding rule (DNAT).
#[derive(Debug, Clone)]
pub struct DnatRule {
    /// Protocol (TCP/UDP).
    pub protocol: Protocol,
    /// Host port to listen on.
    pub host_port: u16,
    /// Host interface (optional, None for all interfaces).
    pub host_interface: Option<String>,
    /// Guest IP address.
    pub guest_ip: Ipv4Addr,
    /// Guest port.
    pub guest_port: u16,
}

impl DnatRule {
    /// Creates a new DNAT rule for port forwarding.
    #[must_use]
    pub fn new(protocol: Protocol, host_port: u16, guest_ip: Ipv4Addr, guest_port: u16) -> Self {
        Self {
            protocol,
            host_port,
            host_interface: None,
            guest_ip,
            guest_port,
        }
    }

    /// Sets the host interface for this rule.
    #[must_use]
    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.host_interface = Some(interface.into());
        self
    }
}

/// Forward rule for allowing traffic between interfaces.
#[derive(Debug, Clone)]
pub struct ForwardRule {
    /// Input interface.
    pub in_interface: String,
    /// Output interface.
    pub out_interface: String,
}

/// Linux firewall manager.
///
/// Manages iptables/nftables rules for NAT, port forwarding, and filtering.
///
/// # Example
///
/// ```no_run
/// use arcbox_net::linux::{LinuxFirewall, NatRule, DnatRule, Protocol};
/// use ipnetwork::Ipv4Network;
///
/// let mut firewall = LinuxFirewall::new().unwrap();
///
/// // Enable IP forwarding
/// firewall.enable_ip_forward().unwrap();
///
/// // Setup custom chains
/// firewall.setup().unwrap();
///
/// // Add NAT rule
/// let nat_rule = NatRule::masquerade("192.168.64.0/24".parse().unwrap(), "eth0");
/// firewall.add_nat_rule(&nat_rule).unwrap();
///
/// // Add port forwarding
/// let dnat_rule = DnatRule::new(Protocol::Tcp, 8080, "192.168.64.2".parse().unwrap(), 80);
/// firewall.add_dnat_rule(&dnat_rule).unwrap();
///
/// // Cleanup
/// firewall.teardown().unwrap();
/// ```
pub struct LinuxFirewall {
    /// Firewall backend (iptables or nftables).
    backend: FirewallBackend,
    /// Whether the firewall has been set up.
    setup_complete: bool,
}

impl LinuxFirewall {
    /// Creates a new firewall manager.
    ///
    /// Automatically detects the available backend.
    ///
    /// # Errors
    ///
    /// Returns an error if no firewall backend is available.
    pub fn new() -> Result<Self> {
        Self::with_backend(FirewallBackend::detect())
    }

    /// Creates a firewall manager with a specific backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend is not available.
    pub fn with_backend(backend: FirewallBackend) -> Result<Self> {
        // Verify backend is available
        let cmd = match backend {
            FirewallBackend::Iptables => "iptables",
            FirewallBackend::Nftables => "nft",
        };

        let output = Command::new(cmd).arg("--version").output().map_err(|e| {
            NetError::Firewall(format!("{} not available: {}", cmd, e))
        })?;

        if !output.status.success() {
            return Err(NetError::Firewall(format!("{} check failed", cmd)));
        }

        tracing::info!("Using firewall backend: {:?}", backend);

        Ok(Self {
            backend,
            setup_complete: false,
        })
    }

    /// Returns the firewall backend.
    #[must_use]
    pub fn backend(&self) -> FirewallBackend {
        self.backend
    }

    /// Sets up the custom chains for ArcBox.
    ///
    /// Creates custom chains in the nat and filter tables.
    ///
    /// # Errors
    ///
    /// Returns an error if chain creation fails.
    pub fn setup(&mut self) -> Result<()> {
        match self.backend {
            FirewallBackend::Iptables => self.setup_iptables(),
            FirewallBackend::Nftables => self.setup_nftables(),
        }?;

        self.setup_complete = true;
        Ok(())
    }

    /// Sets up iptables chains.
    fn setup_iptables(&self) -> Result<()> {
        // Create custom chains
        let chains = [
            ("nat", format!("{}_PREROUTING", CHAIN_PREFIX)),
            ("nat", format!("{}_POSTROUTING", CHAIN_PREFIX)),
            ("filter", format!("{}_FORWARD", CHAIN_PREFIX)),
        ];

        for (table, chain) in &chains {
            // Create chain (ignore error if exists)
            let _ = self.run_iptables(&["-t", table, "-N", chain]);

            // Flush chain
            self.run_iptables(&["-t", table, "-F", chain])?;
        }

        // Jump to custom chains from built-in chains
        // Check if jump rule already exists before adding
        let jump_rules = [
            ("nat", "PREROUTING", format!("{}_PREROUTING", CHAIN_PREFIX)),
            (
                "nat",
                "POSTROUTING",
                format!("{}_POSTROUTING", CHAIN_PREFIX),
            ),
            ("filter", "FORWARD", format!("{}_FORWARD", CHAIN_PREFIX)),
        ];

        for (table, builtin, custom) in &jump_rules {
            // Check if rule exists
            let check = self.run_iptables(&["-t", table, "-C", builtin, "-j", custom]);
            if check.is_err() {
                // Rule doesn't exist, add it
                self.run_iptables(&["-t", table, "-I", builtin, "1", "-j", custom])?;
            }
        }

        tracing::debug!("iptables chains set up");
        Ok(())
    }

    /// Sets up nftables table and chains.
    fn setup_nftables(&self) -> Result<()> {
        // Create table
        let _ = self.run_nft(&["add", "table", "ip", "arcbox"]);

        // Create chains
        let chains = [
            "add chain ip arcbox prerouting { type nat hook prerouting priority -100; }",
            "add chain ip arcbox postrouting { type nat hook postrouting priority 100; }",
            "add chain ip arcbox forward { type filter hook forward priority 0; }",
        ];

        for chain_cmd in &chains {
            let _ = self.run_nft(&chain_cmd.split_whitespace().collect::<Vec<_>>());
        }

        tracing::debug!("nftables table and chains set up");
        Ok(())
    }

    /// Tears down all ArcBox firewall rules and chains.
    ///
    /// # Errors
    ///
    /// Returns an error if cleanup fails.
    pub fn teardown(&mut self) -> Result<()> {
        match self.backend {
            FirewallBackend::Iptables => self.teardown_iptables(),
            FirewallBackend::Nftables => self.teardown_nftables(),
        }?;

        self.setup_complete = false;
        Ok(())
    }

    /// Tears down iptables chains.
    fn teardown_iptables(&self) -> Result<()> {
        // Remove jump rules from built-in chains
        let jump_rules = [
            ("nat", "PREROUTING", format!("{}_PREROUTING", CHAIN_PREFIX)),
            (
                "nat",
                "POSTROUTING",
                format!("{}_POSTROUTING", CHAIN_PREFIX),
            ),
            ("filter", "FORWARD", format!("{}_FORWARD", CHAIN_PREFIX)),
        ];

        for (table, builtin, custom) in &jump_rules {
            let _ = self.run_iptables(&["-t", table, "-D", builtin, "-j", custom]);
        }

        // Flush and delete custom chains
        let chains = [
            ("nat", format!("{}_PREROUTING", CHAIN_PREFIX)),
            ("nat", format!("{}_POSTROUTING", CHAIN_PREFIX)),
            ("filter", format!("{}_FORWARD", CHAIN_PREFIX)),
        ];

        for (table, chain) in &chains {
            let _ = self.run_iptables(&["-t", table, "-F", chain]);
            let _ = self.run_iptables(&["-t", table, "-X", chain]);
        }

        tracing::debug!("iptables chains torn down");
        Ok(())
    }

    /// Tears down nftables table.
    fn teardown_nftables(&self) -> Result<()> {
        let _ = self.run_nft(&["delete", "table", "ip", "arcbox"]);

        tracing::debug!("nftables table deleted");
        Ok(())
    }

    /// Enables IP forwarding in the kernel.
    ///
    /// # Errors
    ///
    /// Returns an error if the sysctl cannot be written.
    pub fn enable_ip_forward(&self) -> Result<()> {
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").map_err(|e| {
            NetError::Firewall(format!("failed to enable IP forwarding: {}", e))
        })?;

        tracing::debug!("IP forwarding enabled");
        Ok(())
    }

    /// Disables IP forwarding in the kernel.
    ///
    /// # Errors
    ///
    /// Returns an error if the sysctl cannot be written.
    pub fn disable_ip_forward(&self) -> Result<()> {
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "0").map_err(|e| {
            NetError::Firewall(format!("failed to disable IP forwarding: {}", e))
        })?;

        tracing::debug!("IP forwarding disabled");
        Ok(())
    }

    /// Adds a NAT (MASQUERADE/SNAT) rule.
    ///
    /// # Errors
    ///
    /// Returns an error if the rule cannot be added.
    pub fn add_nat_rule(&mut self, rule: &NatRule) -> Result<()> {
        match self.backend {
            FirewallBackend::Iptables => self.add_nat_rule_iptables(rule),
            FirewallBackend::Nftables => self.add_nat_rule_nftables(rule),
        }
    }

    /// Adds NAT rule using iptables.
    fn add_nat_rule_iptables(&self, rule: &NatRule) -> Result<()> {
        let chain = format!("{}_POSTROUTING", CHAIN_PREFIX);
        let source = rule.source.to_string();

        let mut args = vec![
            "-t",
            "nat",
            "-A",
            &chain,
            "-s",
            &source,
            "-o",
            &rule.out_interface,
        ];

        let target;
        match rule.nat_type {
            NatType::Masquerade => {
                args.extend(&["-j", "MASQUERADE"]);
            }
            NatType::Snat => {
                target = format!(
                    "--to-source {}",
                    rule.snat_addr.expect("SNAT requires snat_addr")
                );
                args.extend(&["-j", "SNAT", &target]);
            }
        }

        self.run_iptables(&args)?;

        tracing::debug!("Added NAT rule: {:?}", rule);
        Ok(())
    }

    /// Adds NAT rule using nftables.
    fn add_nat_rule_nftables(&self, rule: &NatRule) -> Result<()> {
        let source = rule.source.to_string();

        let rule_str = match rule.nat_type {
            NatType::Masquerade => {
                format!(
                    "add rule ip arcbox postrouting ip saddr {} oifname \"{}\" masquerade",
                    source, rule.out_interface
                )
            }
            NatType::Snat => {
                let snat_addr = rule.snat_addr.expect("SNAT requires snat_addr");
                format!(
                    "add rule ip arcbox postrouting ip saddr {} oifname \"{}\" snat to {}",
                    source, rule.out_interface, snat_addr
                )
            }
        };

        self.run_nft(&rule_str.split_whitespace().collect::<Vec<_>>())?;

        tracing::debug!("Added NAT rule: {:?}", rule);
        Ok(())
    }

    /// Removes a NAT rule.
    ///
    /// # Errors
    ///
    /// Returns an error if the rule cannot be removed.
    pub fn remove_nat_rule(&mut self, rule: &NatRule) -> Result<()> {
        match self.backend {
            FirewallBackend::Iptables => self.remove_nat_rule_iptables(rule),
            FirewallBackend::Nftables => self.remove_nat_rule_nftables(rule),
        }
    }

    /// Removes NAT rule using nftables.
    ///
    /// nftables requires rule handles for deletion. This method queries the
    /// current rules, finds the matching one by its pattern, and deletes it.
    fn remove_nat_rule_nftables(&self, rule: &NatRule) -> Result<()> {
        // Build the pattern to search for in the rule.
        let source_pattern = rule.source.to_string();
        let nat_pattern = match rule.nat_type {
            NatType::Masquerade => "masquerade".to_string(),
            NatType::Snat => format!(
                "snat to {}",
                rule.snat_addr.expect("SNAT requires snat_addr")
            ),
        };

        // Find and delete matching rules in the postrouting chain.
        self.delete_nft_rule_by_pattern("postrouting", &[&source_pattern, &nat_pattern])?;

        tracing::debug!("Removed NAT rule: {:?}", rule);
        Ok(())
    }

    /// Finds and deletes an nftables rule by matching patterns.
    ///
    /// Queries the chain with `-a` flag to get handles, then deletes matching rules.
    fn delete_nft_rule_by_pattern(&self, chain: &str, patterns: &[&str]) -> Result<()> {
        // Query rules with handles.
        let output = Command::new("nft")
            .args(["-a", "list", "chain", "ip", "arcbox", chain])
            .output()
            .map_err(|e| NetError::Firewall(format!("Failed to list nft rules: {}", e)))?;

        if !output.status.success() {
            // Chain might not exist, which is fine.
            return Ok(());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse output to find matching rules.
        // nftables output format: "... handle <N>"
        for line in stdout.lines() {
            // Check if all patterns match this line.
            let matches = patterns.iter().all(|p| line.contains(p));

            if matches {
                // Extract handle from the line.
                if let Some(handle) = Self::extract_nft_handle(line) {
                    tracing::debug!("Found matching rule with handle {}: {}", handle, line.trim());

                    // Delete by handle.
                    let result = Command::new("nft")
                        .args(["delete", "rule", "ip", "arcbox", chain, "handle", &handle.to_string()])
                        .output();

                    match result {
                        Ok(out) if out.status.success() => {
                            tracing::debug!("Deleted nft rule with handle {}", handle);
                        }
                        Ok(out) => {
                            let stderr = String::from_utf8_lossy(&out.stderr);
                            tracing::warn!("Failed to delete nft rule {}: {}", handle, stderr);
                        }
                        Err(e) => {
                            tracing::warn!("Failed to run nft delete: {}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Extracts the handle number from an nftables rule line.
    ///
    /// Line format: "... # handle 123"
    fn extract_nft_handle(line: &str) -> Option<u64> {
        // Look for "handle" followed by a number.
        let parts: Vec<&str> = line.split_whitespace().collect();
        for i in 0..parts.len().saturating_sub(1) {
            if parts[i] == "handle" {
                return parts[i + 1].parse().ok();
            }
        }
        None
    }

    /// Removes NAT rule using iptables.
    fn remove_nat_rule_iptables(&self, rule: &NatRule) -> Result<()> {
        let chain = format!("{}_POSTROUTING", CHAIN_PREFIX);
        let source = rule.source.to_string();

        let mut args = vec![
            "-t",
            "nat",
            "-D",
            &chain,
            "-s",
            &source,
            "-o",
            &rule.out_interface,
        ];

        match rule.nat_type {
            NatType::Masquerade => {
                args.extend(&["-j", "MASQUERADE"]);
            }
            NatType::Snat => {
                let target = format!(
                    "--to-source {}",
                    rule.snat_addr.expect("SNAT requires snat_addr")
                );
                args.extend(&["-j", "SNAT"]);
                args.push(&target);
            }
        }

        self.run_iptables(&args)?;

        tracing::debug!("Removed NAT rule: {:?}", rule);
        Ok(())
    }

    /// Adds a port forwarding (DNAT) rule.
    ///
    /// # Errors
    ///
    /// Returns an error if the rule cannot be added.
    pub fn add_dnat_rule(&mut self, rule: &DnatRule) -> Result<()> {
        match self.backend {
            FirewallBackend::Iptables => self.add_dnat_rule_iptables(rule),
            FirewallBackend::Nftables => self.add_dnat_rule_nftables(rule),
        }
    }

    /// Adds DNAT rule using iptables.
    fn add_dnat_rule_iptables(&self, rule: &DnatRule) -> Result<()> {
        let chain = format!("{}_PREROUTING", CHAIN_PREFIX);
        let protocols = match rule.protocol {
            Protocol::Tcp => vec!["tcp"],
            Protocol::Udp => vec!["udp"],
            Protocol::Both => vec!["tcp", "udp"],
        };

        for proto in protocols {
            let mut args = vec!["-t", "nat", "-A", &chain];

            if let Some(ref iface) = rule.host_interface {
                args.extend(&["-i", iface]);
            }

            let dport = rule.host_port.to_string();
            let to_dest = format!("{}:{}", rule.guest_ip, rule.guest_port);

            args.extend(&["-p", proto, "--dport", &dport, "-j", "DNAT", "--to-destination", &to_dest]);

            self.run_iptables(&args)?;
        }

        tracing::debug!("Added DNAT rule: {:?}", rule);
        Ok(())
    }

    /// Adds DNAT rule using nftables.
    fn add_dnat_rule_nftables(&self, rule: &DnatRule) -> Result<()> {
        let protocols = match rule.protocol {
            Protocol::Tcp => vec!["tcp"],
            Protocol::Udp => vec!["udp"],
            Protocol::Both => vec!["tcp", "udp"],
        };

        for proto in protocols {
            let mut rule_str = String::from("add rule ip arcbox prerouting");

            if let Some(ref iface) = rule.host_interface {
                rule_str.push_str(&format!(" iifname \"{}\"", iface));
            }

            rule_str.push_str(&format!(
                " {} dport {} dnat to {}:{}",
                proto, rule.host_port, rule.guest_ip, rule.guest_port
            ));

            self.run_nft(&rule_str.split_whitespace().collect::<Vec<_>>())?;
        }

        tracing::debug!("Added DNAT rule: {:?}", rule);
        Ok(())
    }

    /// Removes a port forwarding (DNAT) rule.
    ///
    /// # Errors
    ///
    /// Returns an error if the rule cannot be removed.
    pub fn remove_dnat_rule(&mut self, rule: &DnatRule) -> Result<()> {
        match self.backend {
            FirewallBackend::Iptables => self.remove_dnat_rule_iptables(rule),
            FirewallBackend::Nftables => self.remove_dnat_rule_nftables(rule),
        }
    }

    /// Removes DNAT rule using nftables.
    fn remove_dnat_rule_nftables(&self, rule: &DnatRule) -> Result<()> {
        let protocols = match rule.protocol {
            Protocol::Tcp => vec!["tcp"],
            Protocol::Udp => vec!["udp"],
            Protocol::Both => vec!["tcp", "udp"],
        };

        for proto in protocols {
            // Build patterns to match the rule.
            let dport_pattern = format!("dport {}", rule.host_port);
            let dnat_pattern = format!("dnat to {}:{}", rule.guest_ip, rule.guest_port);

            // Find and delete matching rules in the prerouting chain.
            self.delete_nft_rule_by_pattern("prerouting", &[proto, &dport_pattern, &dnat_pattern])?;
        }

        tracing::debug!("Removed DNAT rule: {:?}", rule);
        Ok(())
    }

    /// Removes DNAT rule using iptables.
    fn remove_dnat_rule_iptables(&self, rule: &DnatRule) -> Result<()> {
        let chain = format!("{}_PREROUTING", CHAIN_PREFIX);
        let protocols = match rule.protocol {
            Protocol::Tcp => vec!["tcp"],
            Protocol::Udp => vec!["udp"],
            Protocol::Both => vec!["tcp", "udp"],
        };

        for proto in protocols {
            let mut args = vec!["-t", "nat", "-D", &chain];

            if let Some(ref iface) = rule.host_interface {
                args.extend(&["-i", iface]);
            }

            let dport = rule.host_port.to_string();
            let to_dest = format!("{}:{}", rule.guest_ip, rule.guest_port);

            args.extend(&["-p", proto, "--dport", &dport, "-j", "DNAT", "--to-destination", &to_dest]);

            let _ = self.run_iptables(&args);
        }

        tracing::debug!("Removed DNAT rule: {:?}", rule);
        Ok(())
    }

    /// Adds a FORWARD rule for allowing traffic between interfaces.
    ///
    /// # Errors
    ///
    /// Returns an error if the rule cannot be added.
    pub fn add_forward_rule(&mut self, in_if: &str, out_if: &str) -> Result<()> {
        match self.backend {
            FirewallBackend::Iptables => {
                let chain = format!("{}_FORWARD", CHAIN_PREFIX);

                // Allow established/related connections
                self.run_iptables(&[
                    "-t", "filter", "-A", &chain, "-i", out_if, "-o", in_if,
                    "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT",
                ])?;

                // Allow new connections from internal to external
                self.run_iptables(&[
                    "-t", "filter", "-A", &chain, "-i", in_if, "-o", out_if, "-j", "ACCEPT",
                ])?;
            }
            FirewallBackend::Nftables => {
                let rules = [
                    format!(
                        "add rule ip arcbox forward iifname \"{}\" oifname \"{}\" ct state related,established accept",
                        out_if, in_if
                    ),
                    format!(
                        "add rule ip arcbox forward iifname \"{}\" oifname \"{}\" accept",
                        in_if, out_if
                    ),
                ];

                for rule in &rules {
                    self.run_nft(&rule.split_whitespace().collect::<Vec<_>>())?;
                }
            }
        }

        tracing::debug!("Added forward rule: {} <-> {}", in_if, out_if);
        Ok(())
    }

    /// Runs an iptables command.
    fn run_iptables(&self, args: &[&str]) -> Result<()> {
        let output = Command::new("iptables").args(args).output().map_err(|e| {
            NetError::Firewall(format!("failed to run iptables: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NetError::Firewall(format!(
                "iptables {} failed: {}",
                args.join(" "),
                stderr
            )));
        }

        Ok(())
    }

    /// Runs an nft command.
    fn run_nft(&self, args: &[&str]) -> Result<()> {
        let output = Command::new("nft").args(args).output().map_err(|e| {
            NetError::Firewall(format!("failed to run nft: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NetError::Firewall(format!(
                "nft {} failed: {}",
                args.join(" "),
                stderr
            )));
        }

        Ok(())
    }
}

impl Drop for LinuxFirewall {
    fn drop(&mut self) {
        // Don't automatically teardown - explicit cleanup is preferred
        if self.setup_complete {
            tracing::debug!("LinuxFirewall dropped, rules still active");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_rule_masquerade() {
        let rule = NatRule::masquerade("192.168.64.0/24".parse().unwrap(), "eth0");
        assert_eq!(rule.nat_type, NatType::Masquerade);
        assert_eq!(rule.out_interface, "eth0");
        assert!(rule.snat_addr.is_none());
    }

    #[test]
    fn test_nat_rule_snat() {
        let rule = NatRule::snat(
            "192.168.64.0/24".parse().unwrap(),
            "eth0",
            "10.0.0.1".parse().unwrap(),
        );
        assert_eq!(rule.nat_type, NatType::Snat);
        assert_eq!(rule.snat_addr, Some("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_dnat_rule() {
        let rule = DnatRule::new(Protocol::Tcp, 8080, "192.168.64.2".parse().unwrap(), 80);
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert_eq!(rule.host_port, 8080);
        assert_eq!(rule.guest_port, 80);
    }

    #[test]
    fn test_protocol_as_str() {
        assert_eq!(Protocol::Tcp.as_str(), "tcp");
        assert_eq!(Protocol::Udp.as_str(), "udp");
        assert_eq!(Protocol::Both.as_str(), "all");
    }
}
