//! DNS resolver management commands.
//!
//! Manages `/etc/resolver/arcbox.local` for `*.arcbox.local` DNS resolution.
//! The resolver file points to `127.0.0.1:5553` where the ArcBox daemon
//! provides DNS service.
//!
//! - `abctl dns install`   — create resolver file (requires sudo)
//! - `abctl dns uninstall` — remove resolver file (requires sudo)
//! - `abctl dns status`    — check resolver file and DNS reachability

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arcbox_constants::paths::HostLayout;
use clap::Subcommand;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use macos_resolver::{FileResolver, ResolverConfig, to_env_prefix};
use serde::Serialize;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use super::OutputFormat;

/// Prefix for marker comment and environment variable namespace.
///
/// - Marker: `# managed by arcbox`
/// - Env vars: `ARCBOX_RESOLVER_DIR`, `ARCBOX_DNS_PORT`, `ARCBOX_DNS_DOMAIN`
const PREFIX: &str = "arcbox";

/// Default DNS port (overridable via `ARCBOX_DNS_PORT`).
const DEFAULT_DNS_PORT: u16 = 5553;

/// Default domain suffix (overridable via `ARCBOX_DNS_DOMAIN`).
const DEFAULT_DNS_DOMAIN: &str = "arcbox.local";

const DNS_PROBE_ID: u16 = 0xabcd;
const DNS_PROBE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum DnsHealth {
    Healthy,
    Negative {
        response_code: u16,
        description: String,
    },
    DaemonDown,
    ListenerAbsent,
    TimedOut,
    Malformed {
        error: String,
    },
    Io {
        error: String,
    },
}

impl DnsHealth {
    fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    fn malformed(error: impl Into<String>) -> Self {
        Self::Malformed {
            error: error.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct DnsStatus {
    pub ready: bool,
    pub domain: String,
    pub resolver_path: String,
    pub resolver_installed: bool,
    pub server_address: String,
    pub query_name: String,
    pub health: DnsHealth,
}

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
pub async fn execute(cmd: DnsCommands, format: OutputFormat) -> Result<()> {
    match cmd {
        DnsCommands::Install => execute_install().await,
        DnsCommands::Uninstall => execute_uninstall().await,
        DnsCommands::Status => execute_status(format).await,
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
            eprintln!("  sudo abctl dns install");
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
            eprintln!("  sudo abctl dns uninstall");
            std::process::exit(1);
        }
        Err(e) => Err(e).context("Failed to uninstall DNS resolver"),
    }
}

async fn execute_status(format: OutputFormat) -> Result<()> {
    let status = inspect_status().await;

    match format {
        OutputFormat::Table => print_status(&status),
        OutputFormat::Json => println!("{}", serde_json::to_string(&status)?),
        OutputFormat::Quiet => bail!("quiet output is not supported for dns status"),
    }

    if status.ready {
        Ok(())
    } else {
        bail!("DNS status is not ready")
    }
}

pub(super) async fn inspect_status() -> DnsStatus {
    let resolver = FileResolver::new(PREFIX);
    let domain = dns_domain();
    let port = dns_port();
    let resolver_installed = resolver.is_registered(&domain);
    let resolver_path = resolver.resolver_dir().join(&domain);
    let server: SocketAddr = (Ipv4Addr::LOCALHOST, port).into();
    let query_name = format!("host.{domain}");
    let health = daemon_health(
        probe_dns(server, &query_name, DNS_PROBE_TIMEOUT).await,
        super::daemon::daemon_is_alive(&HostLayout::from_env_or_default().lock_file),
    );

    DnsStatus {
        ready: resolver_installed && health.is_healthy(),
        domain,
        resolver_path: resolver_path.display().to_string(),
        resolver_installed,
        server_address: server.to_string(),
        query_name,
        health,
    }
}

fn print_status(status: &DnsStatus) {
    let installed = if status.resolver_installed {
        "installed"
    } else {
        "not installed"
    };
    println!("Resolver file: {installed} ({})", status.resolver_path);

    let server = match &status.health {
        DnsHealth::Healthy => format!(
            "healthy ({} answered A for {})",
            status.server_address, status.query_name
        ),
        DnsHealth::Negative {
            response_code,
            description,
        } => format!("negative response (code {response_code}: {description})"),
        DnsHealth::DaemonDown => "daemon not running".to_string(),
        DnsHealth::ListenerAbsent => format!("no listener at {}", status.server_address),
        DnsHealth::TimedOut => format!("timed out at {}", status.server_address),
        DnsHealth::Malformed { error } => format!("malformed response ({error})"),
        DnsHealth::Io { error } => format!("probe failed ({error})"),
    };
    println!("DNS server:    {server}");
    println!(
        "Status:        {}",
        if status.ready { "ready" } else { "not ready" }
    );

    if !status.resolver_installed {
        println!();
        println!(
            "Run 'sudo abctl dns install' to enable *.{} DNS resolution.",
            status.domain
        );
    }

    if matches!(&status.health, DnsHealth::DaemonDown) {
        println!("\nStart the ArcBox daemon to provide DNS service.");
    }
}

async fn probe_dns(address: SocketAddr, query_name: &str, deadline: Duration) -> DnsHealth {
    let (expected_query, request) = match build_probe_query(query_name) {
        Ok(request) => request,
        Err(error) => return DnsHealth::malformed(error),
    };

    let socket = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await {
        Ok(socket) => socket,
        Err(error) => return transport_error("bind", error),
    };
    if let Err(error) = socket.connect(address).await {
        return transport_error("connect", error);
    }
    if let Err(error) = socket.send(&request).await {
        return transport_error("send", error);
    }

    let mut response = [0_u8; 4096];
    match timeout(deadline, socket.recv(&mut response)).await {
        Err(_) => DnsHealth::TimedOut,
        Ok(Err(error)) => transport_error("receive", error),
        Ok(Ok(length)) => classify_response(&response[..length], &expected_query),
    }
}

fn build_probe_query(query_name: &str) -> std::result::Result<(Query, Vec<u8>), String> {
    let mut name = Name::from_ascii(query_name).map_err(|error| error.to_string())?;
    name.set_fqdn(true);
    let query = Query::query(name, RecordType::A);
    let mut message = Message::new(DNS_PROBE_ID, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(query.clone());
    let wire = message.to_vec().map_err(|error| error.to_string())?;
    Ok((query, wire))
}

fn classify_response(wire: &[u8], expected_query: &Query) -> DnsHealth {
    let response = match Message::from_vec(wire) {
        Ok(response) => response,
        Err(error) => return DnsHealth::malformed(error.to_string()),
    };

    if response.metadata.id != DNS_PROBE_ID {
        return DnsHealth::malformed(format!(
            "transaction ID mismatch: expected {DNS_PROBE_ID:#06x}, got {:#06x}",
            response.metadata.id
        ));
    }
    if response.metadata.message_type != MessageType::Response {
        return DnsHealth::malformed("packet is not a DNS response");
    }
    if response.metadata.truncation {
        return DnsHealth::malformed("UDP response is truncated");
    }
    if response.queries.as_slice() != std::slice::from_ref(expected_query) {
        return DnsHealth::malformed("response question does not match the request");
    }

    let response_code = response.metadata.response_code;
    if response_code != ResponseCode::NoError {
        return DnsHealth::Negative {
            response_code: u16::from(response_code),
            description: response_code.to_string(),
        };
    }

    if response.answers.iter().any(|answer| {
        &answer.name == expected_query.name()
            && answer.dns_class == expected_query.query_class()
            && answer.record_type() == RecordType::A
    }) {
        DnsHealth::Healthy
    } else {
        DnsHealth::Negative {
            response_code: u16::from(ResponseCode::NoError),
            description: "NODATA (no matching A answer)".to_string(),
        }
    }
}

fn transport_error(operation: &str, error: io::Error) -> DnsHealth {
    if error.kind() == io::ErrorKind::ConnectionRefused {
        DnsHealth::ListenerAbsent
    } else {
        DnsHealth::Io {
            error: format!("{operation}: {error}"),
        }
    }
}

fn daemon_health(health: DnsHealth, daemon_alive: bool) -> DnsHealth {
    if !daemon_alive && matches!(health, DnsHealth::ListenerAbsent | DnsHealth::TimedOut) {
        DnsHealth::DaemonDown
    } else {
        health
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use hickory_proto::rr::{RData, Record, rdata::A};

    use super::*;

    fn query() -> Query {
        build_probe_query("host.arcbox.local").unwrap().0
    }

    fn response_wire(query: &Query, response_code: ResponseCode, answer: bool) -> Vec<u8> {
        let mut response = Message::response(DNS_PROBE_ID, OpCode::Query);
        response.metadata.response_code = response_code;
        response.add_query(query.clone());
        if answer {
            response.add_answer(Record::from_rdata(
                query.name().clone(),
                60,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
            ));
        }
        response.to_vec().unwrap()
    }

    fn is_malformed(health: DnsHealth) -> bool {
        matches!(health, DnsHealth::Malformed { .. })
    }

    fn negative_code(health: DnsHealth) -> Option<u16> {
        match health {
            DnsHealth::Negative { response_code, .. } => Some(response_code),
            _ => None,
        }
    }

    #[test]
    fn validates_positive_and_negative_dns_responses() {
        let query = query();
        let classify =
            |code, answer| classify_response(&response_wire(&query, code, answer), &query);
        assert_eq!(classify(ResponseCode::NoError, true), DnsHealth::Healthy);
        assert_eq!(
            negative_code(classify(ResponseCode::NXDomain, false)),
            Some(3)
        );
        assert_eq!(
            negative_code(classify(ResponseCode::NoError, false)),
            Some(0)
        );
    }

    #[test]
    fn rejects_malformed_and_mismatched_dns_responses() {
        let query = query();
        assert!(is_malformed(classify_response(&[0, 1, 2], &query)));

        let mut wrong_id = Message::response(DNS_PROBE_ID + 1, OpCode::Query);
        wrong_id.add_query(query.clone());
        assert!(is_malformed(classify_response(
            &wrong_id.to_vec().unwrap(),
            &query
        )));
    }

    #[test]
    fn classifies_transport_and_daemon_state() {
        let refused = io::Error::from(io::ErrorKind::ConnectionRefused);
        let health = transport_error("receive", refused);
        assert_eq!(health, DnsHealth::ListenerAbsent);
        assert_eq!(daemon_health(health.clone(), false), DnsHealth::DaemonDown);
        assert_eq!(daemon_health(health, true), DnsHealth::ListenerAbsent);
        assert_eq!(
            daemon_health(DnsHealth::TimedOut, true),
            DnsHealth::TimedOut
        );
    }

    #[test]
    fn serializes_typed_health_status() {
        let health = DnsHealth::Negative {
            response_code: 3,
            description: "NXDomain".to_string(),
        };
        let json = serde_json::to_value(health).unwrap();
        assert_eq!(json["status"], "negative");
        assert_eq!(json["response_code"], 3);
    }

    #[tokio::test]
    async fn probes_a_real_udp_dns_exchange() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = server.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            let (length, peer) = server.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer[..length]).unwrap();
            let query = request.queries.first().unwrap();
            let response = response_wire(query, ResponseCode::NoError, true);
            server.send_to(&response, peer).await.unwrap();
        });

        assert_eq!(
            probe_dns(address, "host.arcbox.local", Duration::from_secs(1)).await,
            DnsHealth::Healthy
        );
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn reports_udp_probe_timeout() {
        let silent_server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = silent_server.local_addr().unwrap();

        assert_eq!(
            probe_dns(address, "host.arcbox.local", Duration::from_millis(20)).await,
            DnsHealth::TimedOut
        );
    }
}
