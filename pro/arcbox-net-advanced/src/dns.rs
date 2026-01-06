//! Advanced DNS features.

use crate::SplitDnsRule;
use std::net::Ipv4Addr;

/// Split DNS resolver.
pub struct SplitDnsResolver {
    rules: Vec<SplitDnsRule>,
    default_servers: Vec<Ipv4Addr>,
}

impl SplitDnsResolver {
    /// Creates a new split DNS resolver.
    #[must_use]
    pub fn new(default_servers: Vec<Ipv4Addr>) -> Self {
        Self {
            rules: Vec::new(),
            default_servers,
        }
    }

    /// Adds a split DNS rule.
    pub fn add_rule(&mut self, rule: SplitDnsRule) {
        self.rules.push(rule);
    }

    /// Resolves which DNS servers to use for a domain.
    #[must_use]
    pub fn servers_for(&self, domain: &str) -> Vec<&str> {
        for rule in &self.rules {
            if domain.ends_with(&rule.domain) {
                return rule.servers.iter().map(String::as_str).collect();
            }
        }
        // Return default servers
        Vec::new()
    }
}
