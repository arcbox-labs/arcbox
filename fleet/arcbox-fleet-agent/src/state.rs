//! Reactive, observable agent state: a single value pushed via `watch`,
//! mirroring `arcbox-api`'s `SetupState`. Every module that owns a
//! transition (enrollment, admission, telemetry) calls straight into this;
//! `FleetStateService::watch` (`control/watch.rs`) is the only reader that
//! turns it into a stream. Settings (a later addition) will push through
//! this same snapshot rather than needing their own notification path.

use std::sync::Arc;

use arcbox_fleet_control_proto::v1::{
    AgentStateSnapshot, Capability, Enrollment, HostTelemetry, InFlightJob, OfferVerdict,
};
use tokio::sync::watch;

/// Bound on `recent_verdicts` so a long-lived agent's snapshot doesn't grow
/// without limit; only recent history is useful for a live status view.
const RECENT_VERDICTS_CAP: usize = 20;

/// Cheap-to-clone handle onto the agent's observable state. Every setter is
/// synchronous (`watch::Sender::send_modify` never awaits), so it can be
/// called from non-async contexts like `Drop` impls.
#[derive(Clone)]
pub struct AgentState {
    tx: Arc<watch::Sender<AgentStateSnapshot>>,
}

impl AgentState {
    /// A fresh, unenrolled snapshot — no credential, nothing running.
    pub fn new() -> Self {
        let (tx, _) = watch::channel(AgentStateSnapshot {
            enrollment: Enrollment::Unenrolled as i32,
            machine_id: String::new(),
            draining: false,
            capabilities: Vec::new(),
            in_flight: Vec::new(),
            recent_verdicts: Vec::new(),
            telemetry: None,
        });
        Self { tx: Arc::new(tx) }
    }

    /// Subscribe to future changes. `FleetStateService::watch` yields the
    /// current value first (`borrow_and_update`), then one per change.
    pub fn subscribe(&self) -> watch::Receiver<AgentStateSnapshot> {
        self.tx.subscribe()
    }

    /// A snapshot of the current state.
    pub fn current(&self) -> AgentStateSnapshot {
        self.tx.borrow().clone()
    }

    pub fn set_enrollment(&self, enrollment: Enrollment, machine_id: &str) {
        self.tx.send_modify(|s| {
            s.enrollment = enrollment as i32;
            machine_id.clone_into(&mut s.machine_id);
        });
    }

    pub fn set_draining(&self, draining: bool) {
        self.tx.send_modify(|s| s.draining = draining);
    }

    /// Advertised capabilities are static for an attachment's lifetime, so
    /// this is set once rather than tracked incrementally.
    pub fn set_capabilities(&self, capabilities: Vec<Capability>) {
        self.tx.send_modify(|s| s.capabilities = capabilities);
    }

    pub fn add_in_flight(&self, job: InFlightJob) {
        self.tx.send_modify(|s| s.in_flight.push(job));
    }

    pub fn remove_in_flight(&self, job_id: &str) {
        self.tx
            .send_modify(|s| s.in_flight.retain(|j| j.job_id != job_id));
    }

    /// Append a verdict, dropping the oldest once [`RECENT_VERDICTS_CAP`] is
    /// exceeded. Most-recent-last.
    pub fn push_verdict(&self, verdict: OfferVerdict) {
        self.tx.send_modify(|s| {
            s.recent_verdicts.push(verdict);
            if s.recent_verdicts.len() > RECENT_VERDICTS_CAP {
                s.recent_verdicts.remove(0);
            }
        });
    }

    pub fn set_telemetry(&self, telemetry: HostTelemetry) {
        self.tx.send_modify(|s| s.telemetry = Some(telemetry));
    }
}

impl Default for AgentState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(id: &str) -> InFlightJob {
        InFlightJob {
            job_id: id.to_owned(),
            os: "darwin".to_owned(),
            arch: "arm64".to_owned(),
        }
    }

    fn verdict(id: &str) -> OfferVerdict {
        OfferVerdict {
            job_id: id.to_owned(),
            accepted: true,
            reason: String::new(),
        }
    }

    #[test]
    fn starts_unenrolled_and_empty() {
        let snap = AgentState::new().current();
        assert_eq!(snap.enrollment, Enrollment::Unenrolled as i32);
        assert_eq!(snap.machine_id, "");
        assert!(!snap.draining);
        assert!(snap.capabilities.is_empty());
        assert!(snap.in_flight.is_empty());
        assert!(snap.recent_verdicts.is_empty());
        assert!(snap.telemetry.is_none());
    }

    #[test]
    fn in_flight_add_and_remove_round_trips() {
        let state = AgentState::new();
        state.add_in_flight(job("rjob_a"));
        state.add_in_flight(job("rjob_b"));
        assert_eq!(state.current().in_flight.len(), 2);

        state.remove_in_flight("rjob_a");
        let remaining = state.current().in_flight;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].job_id, "rjob_b");
    }

    #[test]
    fn recent_verdicts_cap_drops_oldest_and_keeps_most_recent_last() {
        let state = AgentState::new();
        for i in 0..RECENT_VERDICTS_CAP + 5 {
            state.push_verdict(verdict(&format!("rjob_{i}")));
        }
        let verdicts = state.current().recent_verdicts;
        assert_eq!(verdicts.len(), RECENT_VERDICTS_CAP);
        assert_eq!(verdicts.first().unwrap().job_id, "rjob_5");
        assert_eq!(
            verdicts.last().unwrap().job_id,
            format!("rjob_{}", RECENT_VERDICTS_CAP + 4)
        );
    }

    #[test]
    fn set_enrollment_updates_machine_id() {
        let state = AgentState::new();
        state.set_enrollment(Enrollment::Attaching, "fltm_test");
        let snap = state.current();
        assert_eq!(snap.enrollment, Enrollment::Attaching as i32);
        assert_eq!(snap.machine_id, "fltm_test");
    }

    #[test]
    fn set_draining_toggles() {
        let state = AgentState::new();
        state.set_draining(true);
        assert!(state.current().draining);
        state.set_draining(false);
        assert!(!state.current().draining);
    }
}
