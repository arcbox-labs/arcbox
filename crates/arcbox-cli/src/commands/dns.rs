//! DNS resolver management commands.
//!
//! Manages `/etc/resolver/arcbox.local` for `*.arcbox.local` DNS resolution.
//! The resolver file points to `127.0.0.1:5553` where the ArcBox daemon
//! provides DNS service.
//!
//! - `arcbox dns install`   — create resolver file (requires sudo)
//! - `arcbox dns uninstall` — remove resolver file (requires sudo)
//! - `arcbox dns status`    — check resolver file and DNS reachability

use anyhow::{Context, Result};
use clap::Subcommand;
use macos_resolver::{FileResolver, ResolverConfig, to_env_prefix};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// Prefix for marker comment and environment variable namespace.
///
/// - Marker: `# managed by arcbox`
/// - Env vars: `ARCBOX_RESOLVER_DIR`, `ARCBOX_DNS_PORT`, `ARCBOX_DNS_DOMAIN`
const PREFIX: &str = "arcbox";

/// Default DNS port (overridable via `ARCBOX_DNS_PORT`).
const DEFAULT_DNS_PORT: u16 = 5553;

/// Default domain suffix (overridable via `ARCBOX_DNS_DOMAIN`).
const DEFAULT_DNS_DOMAIN: &str = "arcbox.local";

/// Reads the DNS port from `{PREFIX}_DNS_PORT` or falls back to the default.
fn dns_port() -> u16 {
    let key = format!("{}_DNS_PORT", to_env_prefix(PREFIX));
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_DNS_PORT)
}

/// Reads the DNS domain from `{PREFIX}_DNS_DOMAIN` or falls back to the default.
fn dns_domain() -> String {
    let key = format!("{}_DNS_DOMAIN", to_env_prefix(PREFIX));
    std::env::var(key).unwrap_or_else(|_| DEFAULT_DNS_DOMAIN.to_string())
}

/// DNS resolver management commands.
#[derive(Debug, Subcommand)]
pub enum DnsCommands {
    /// Install the macOS DNS resolver for *.arcbox.local
    Install,

    /// Remove the macOS DNS resolver for *.arcbox.local
    Uninstall,

    /// Check DNS resolver status
    Status,
}

/// Executes the dns subcommand.
pub async fn execute(cmd: DnsCommands) -> Result<()> {
    match cmd {
        DnsCommands::Install => execute_install().await,
        DnsCommands::Uninstall => execute_uninstall().await,
        DnsCommands::Status => execute_status().await,
    }
}

/// Creates `/etc/resolver/<domain>` as a permanent entry.
async fn execute_install() -> Result<()> {
    let resolver = FileResolver::new(PREFIX);
    let domain = dns_domain();
    let port = dns_port();
    let config = ResolverConfig::new(&domain, "127.0.0.1", port);

    match resolver.register_permanent(&config) {
        Ok(()) => {
            println!("Installed DNS resolver: /etc/resolver/{domain}");
            println!("  nameserver 127.0.0.1");
            println!("  port       {port}");
            println!();
            println!("All *.{domain} queries will be routed to the ArcBox DNS server.");
            Ok(())
        }
        Err(ref e) if e.is_permission_denied() => {
            eprintln!("Error: permission denied writing to /etc/resolver/");
            eprintln!();
            eprintln!("Run with sudo:");
            eprintln!("  sudo arcbox dns install");
            std::process::exit(1);
        }
        Err(e) => Err(e).context("Failed to install DNS resolver"),
    }
}

/// Removes `/etc/resolver/<domain>`.
async fn execute_uninstall() -> Result<()> {
    let resolver = FileResolver::new(PREFIX);
    let domain = dns_domain();

    match resolver.unregister(&domain) {
        Ok(()) => {
            println!("Removed DNS resolver: /etc/resolver/{domain}");
            Ok(())
        }
        Err(ref e) if e.is_permission_denied() => {
            eprintln!("Error: permission denied removing /etc/resolver/{domain}");
            eprintln!();
            eprintln!("Run with sudo:");
            eprintln!("  sudo arcbox dns uninstall");
            std::process::exit(1);
        }
        Err(e) => Err(e).context("Failed to uninstall DNS resolver"),
    }
}

/// Checks resolver file presence and DNS server reachability.
async fn execute_status() -> Result<()> {
    let resolver = FileResolver::new(PREFIX);
    let domain = dns_domain();
    let port = dns_port();
    let installed = resolver.is_registered(&domain);

    if installed {
        println!("Resolver file: installed (/etc/resolver/{domain})");
    } else {
        println!("Resolver file: not installed");
    }

    let reachable = is_dns_port_reachable(port);
    if reachable {
        println!("DNS server:    reachable (127.0.0.1:{port})");
    } else {
        println!("DNS server:    not reachable (127.0.0.1:{port})");
    }

    if !installed {
        println!();
        println!("Run 'sudo arcbox dns install' to enable *.{domain} DNS resolution.");
    }
    if !reachable {
        println!();
        println!("Start the ArcBox daemon to provide DNS service on port {port}.");
    }

    Ok(())
}

/// Quick UDP probe to check if something is listening on the DNS port.
fn is_dns_port_reachable(port: u16) -> bool {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
        return false;
    };
    let _ = socket.set_read_timeout(Some(Duration::from_millis(200)));

    // Send a minimal DNS query (just enough to elicit a response).
    // ID=0x1234, flags=0x0100 (standard query), 1 question, QNAME=., QTYPE=A, QCLASS=IN
    let query: [u8; 17] = [
        0x12, 0x34, // ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        0x00, // QNAME: root (.)
        0x00, 0x01, // QTYPE: A
        0x00, 0x01, // QCLASS: IN
    ];

    if socket.send_to(&query, addr).is_err() {
        return false;
    }

    let mut buf = [0u8; 512];
    socket.recv_from(&mut buf).is_ok()
}

/// Checks whether the DNS resolver is installed and prints a hint if not.
///
/// Called from daemon startup to remind users to install the resolver.
pub fn check_resolver_installed() {
    let resolver = FileResolver::new(PREFIX);
    let domain = dns_domain();
    if !resolver.is_registered(&domain) {
        println!("Hint: Run 'sudo arcbox dns install' to enable *.{domain} DNS resolution.");
    }
}
