use std::collections::HashSet;

use arcbox_connect::v1::SandboxCleanupTicket;

pub fn unseen_rescan_tickets(
    sent: &mut HashSet<(String, String)>,
    tickets: Vec<SandboxCleanupTicket>,
) -> Vec<SandboxCleanupTicket> {
    let pending: HashSet<_> = tickets
        .iter()
        .map(|ticket| (ticket.id.clone(), ticket.token.clone()))
        .collect();
    sent.retain(|generation| pending.contains(generation));
    tickets
        .into_iter()
        .filter(|ticket| !sent.contains(&(ticket.id.clone(), ticket.token.clone())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periodic_rescan_discovers_marker_without_terminal_event() {
        let old = SandboxCleanupTicket {
            id: "old".into(),
            token: "old-generation".into(),
            startup: false,
            ..Default::default()
        };
        let new = SandboxCleanupTicket {
            id: "new".into(),
            token: "new-generation".into(),
            startup: false,
            ..Default::default()
        };
        let mut sent = HashSet::from([(old.id.clone(), old.token.clone())]);

        let unseen = unseen_rescan_tickets(&mut sent, vec![old, new.clone()]);

        assert_eq!(unseen, vec![new]);
    }
}
