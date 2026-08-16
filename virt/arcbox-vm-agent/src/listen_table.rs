//! `/proc/net/tcp{,6}` listen-table parsing.
//!
//! The vm-agent answers `WaitForPort` by watching the guest kernel's own
//! listen table — never a connect probe, which would perturb the workload
//! with spurious accepted connections. The text parsing lives here so it
//! is unit-tested on every host platform.

/// TCP state code for `LISTEN` in `/proc/net/tcp` (see `include/net/tcp_states.h`).
const TCP_LISTEN: u32 = 0x0A;

/// True when any socket in `table` — the text of `/proc/net/tcp` or
/// `/proc/net/tcp6` — is LISTENing on local port `port`, whatever the
/// bound address.
#[must_use]
pub fn any_listener_on_port(table: &str, port: u16) -> bool {
    // Header line first; each row is
    // `sl local_address rem_address st ...` with addresses as HEXIP:HEXPORT.
    table.lines().skip(1).any(|line| {
        let mut fields = line.split_whitespace();
        let local = fields.nth(1);
        let state = fields.nth(1);
        let listening = state
            .and_then(|st| u32::from_str_radix(st, 16).ok())
            .is_some_and(|st| st == TCP_LISTEN);
        listening
            && local
                .and_then(|addr| addr.rsplit(':').next())
                .and_then(|p| u16::from_str_radix(p, 16).ok())
                == Some(port)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
   2: 0A00020F:D2F0 8EFB2CCE:01BB 01 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 20 4 30 10 -1
";

    const TCP6: &str = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:5BA0 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22345 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn finds_a_listener_on_any_address() {
        assert!(any_listener_on_port(TCP, 0x1F90)); // 8080 on 0.0.0.0
        assert!(any_listener_on_port(TCP, 53)); // 0x0035 on 127.0.0.1
        assert!(any_listener_on_port(TCP6, 0x5BA0)); // v6 wildcard
    }

    #[test]
    fn established_sockets_do_not_count() {
        // Port 0xD2F0 exists only as an ESTABLISHED (st 01) socket.
        assert!(!any_listener_on_port(TCP, 0xD2F0));
    }

    #[test]
    fn absent_port_is_not_listening() {
        assert!(!any_listener_on_port(TCP, 12345));
        assert!(!any_listener_on_port("", 80));
    }

    #[test]
    fn malformed_rows_are_ignored() {
        assert!(!any_listener_on_port("garbage\nmore : garbage\n:::\n", 80));
    }
}
