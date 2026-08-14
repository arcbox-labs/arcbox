//! Ensures `/etc/resolver/<domain>` points to the daemon's DNS server.

use arcbox_helper::client::{Client, ClientError};

use super::SetupTask;

pub struct DnsResolver {
    pub domain: String,
    pub port: u16,
}

#[async_trait::async_trait]
impl SetupTask for DnsResolver {
    fn name(&self) -> &'static str {
        "DNS resolver"
    }

    fn is_satisfied(&self) -> bool {
        let path = format!("/etc/resolver/{}", self.domain);
        std::fs::read_to_string(&path)
            .is_ok_and(|content| resolver_contents_match(&content, self.port))
    }

    async fn apply(&self, client: &Client) -> Result<(), ClientError> {
        client.dns_install(&self.domain, self.port).await
    }
}

fn resolver_contents_match(contents: &str, port: u16) -> bool {
    let expected_port = format!("port {port}");
    contents
        .lines()
        .map(str::trim)
        .any(|line| line == "nameserver 127.0.0.1")
        && contents
            .lines()
            .map(str::trim)
            .any(|line| line == expected_port)
}

#[cfg(test)]
mod tests {
    use super::resolver_contents_match;

    #[test]
    fn resolver_port_must_match_the_complete_directive() {
        let contents = "nameserver 127.0.0.1\nport 55530\n";

        assert!(resolver_contents_match(contents, 55_530));
        assert!(!resolver_contents_match(contents, 5_553));
    }
}
