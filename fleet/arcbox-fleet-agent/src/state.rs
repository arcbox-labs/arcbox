//! Reactive, observable agent state: a single value pushed via `watch`,
//! mirroring `arcbox-api`'s `SetupState`. Every module that owns a
//! transition (enrollment, admission, telemetry, settings) calls straight
//! into this; `FleetStateService::watch` (`control/watch.rs`) is the only
//! reader that turns it into a stream.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arcbox_fleet_control_proto::v1::{
    AgentSettings, AgentStateSnapshot, BoolSetting, Capability, DockerModeSetting, DoubleSetting,
    Enrollment, HostTelemetry, InFlightJob, OfferVerdict, StringSetting, Uint64Setting,
};
use tokio::sync::watch;

use crate::config::DockerMode;
use crate::settings::PersistedSettings;

/// Bound on `recent_verdicts` so a long-lived agent's snapshot doesn't grow
/// without limit; only recent history is useful for a live status view.
const RECENT_VERDICTS_CAP: usize = 20;

/// `AgentState::new` always populates `settings` fully, unlike `telemetry`
/// (legitimately absent until the first heartbeat) — every accessor below
/// relies on this and panics via this message if it's ever violated.
const SETTINGS_INVARIANT: &str = "AgentState::new always initializes settings";

/// Convert a gateway-facing `DockerMode` into its control-plane
/// counterpart. A plain function, not `From`: `control_proto::DockerMode`
/// is generated in another crate, so Rust's orphan rule blocks
/// implementing a foreign trait for a foreign *target* type here.
fn docker_mode_to_control(mode: DockerMode) -> arcbox_fleet_control_proto::v1::DockerMode {
    match mode {
        DockerMode::Auto => arcbox_fleet_control_proto::v1::DockerMode::Auto,
        DockerMode::Enabled => arcbox_fleet_control_proto::v1::DockerMode::Enabled,
        DockerMode::Disabled => arcbox_fleet_control_proto::v1::DockerMode::Disabled,
    }
}

/// The reverse direction has no such restriction — `DockerMode` (the
/// target here) is local to this crate, so the orphan rule allows a real
/// `From` impl even though the source type is foreign. Unrecognized/absent
/// wire values fall back to `Auto`, matching `AgentConfig::from_env`'s own
/// default.
impl From<arcbox_fleet_control_proto::v1::DockerMode> for DockerMode {
    fn from(mode: arcbox_fleet_control_proto::v1::DockerMode) -> Self {
        match mode {
            arcbox_fleet_control_proto::v1::DockerMode::Enabled => Self::Enabled,
            arcbox_fleet_control_proto::v1::DockerMode::Disabled => Self::Disabled,
            arcbox_fleet_control_proto::v1::DockerMode::Auto
            | arcbox_fleet_control_proto::v1::DockerMode::Unspecified => Self::Auto,
        }
    }
}

/// Parse a wire `DockerMode` i32 that may not be a recognized variant
/// (an older/newer client sent something this build doesn't know) into the
/// internal type, falling back to `Auto`.
pub fn docker_mode_from_wire(raw: i32) -> DockerMode {
    arcbox_fleet_control_proto::v1::DockerMode::try_from(raw)
        .unwrap_or(arcbox_fleet_control_proto::v1::DockerMode::Unspecified)
        .into()
}

fn path_to_setting_value(path: Option<&Path>) -> String {
    path.map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn setting_value_to_path(value: &str) -> Option<PathBuf> {
    (!value.is_empty()).then(|| PathBuf::from(value))
}

/// The always-present settings block. Every accessor goes through these two
/// helpers so the outer [`SETTINGS_INVARIANT`] assertion is spelled once here
/// rather than at each of the ~15 call sites (and each new settable field
/// inherits it for free).
fn settings_of(snapshot: &AgentStateSnapshot) -> &AgentSettings {
    snapshot.settings.as_ref().expect(SETTINGS_INVARIANT)
}

fn settings_mut(snapshot: &mut AgentStateSnapshot) -> &mut AgentSettings {
    snapshot.settings.as_mut().expect(SETTINGS_INVARIANT)
}

/// Cheap-to-clone handle onto the agent's observable state. Every setter is
/// synchronous (`watch::Sender::send_modify` never awaits), so it can be
/// called from non-async contexts like `Drop` impls.
#[derive(Clone)]
pub struct AgentState {
    tx: Arc<watch::Sender<AgentStateSnapshot>>,
}

impl AgentState {
    /// A fresh, unenrolled snapshot — no credential, nothing running.
    /// `seed`'s values populate `settings` with `current == target`
    /// everywhere; callers that resolve a different `current` post-startup
    /// (e.g. `docker_mode`, once `init_docker()` actually runs) update it
    /// separately.
    pub fn new(seed: &PersistedSettings) -> Self {
        let runner_script = path_to_setting_value(seed.runner_script.as_deref());
        let docker_mode = docker_mode_to_control(seed.docker_mode) as i32;
        let settings = AgentSettings {
            load_ceiling: Some(DoubleSetting {
                current: seed.load_ceiling,
                target: seed.load_ceiling,
            }),
            mem_floor_mib: Some(Uint64Setting {
                current: seed.mem_floor_mib,
                target: seed.mem_floor_mib,
            }),
            linux_runner_image: Some(StringSetting {
                current: seed.linux_runner_image.clone(),
                target: seed.linux_runner_image.clone(),
            }),
            gateway: Some(StringSetting {
                current: seed.gateway.clone(),
                target: seed.gateway.clone(),
            }),
            docker_mode: Some(DockerModeSetting {
                current: docker_mode,
                target: docker_mode,
            }),
            runner_script: Some(StringSetting {
                current: runner_script.clone(),
                target: runner_script,
            }),
            participate: Some(BoolSetting {
                current: seed.participate,
                target: seed.participate,
            }),
        };
        let (tx, _) = watch::channel(AgentStateSnapshot {
            enrollment: Enrollment::Unenrolled as i32,
            machine_id: String::new(),
            draining: false,
            capabilities: Vec::new(),
            in_flight: Vec::new(),
            recent_verdicts: Vec::new(),
            telemetry: None,
            settings: Some(settings),
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

    /// The current settings, for `GetSettings`.
    pub fn settings(&self) -> AgentSettings {
        settings_of(&self.tx.borrow()).clone()
    }

    /// The current settings, projected down to their persisted
    /// (`target`-only) shape — what [`crate::settings::SettingsStore`]
    /// writes to disk, and the baseline `FleetSettingsService.UpdateSettings`
    /// computes "effective post-update" values against before applying a
    /// request.
    pub fn persisted_settings(&self) -> PersistedSettings {
        let snapshot = self.tx.borrow();
        let s = settings_of(&snapshot);
        PersistedSettings {
            load_ceiling: s.load_ceiling.as_ref().expect(SETTINGS_INVARIANT).target,
            mem_floor_mib: s.mem_floor_mib.as_ref().expect(SETTINGS_INVARIANT).target,
            linux_runner_image: s
                .linux_runner_image
                .as_ref()
                .expect(SETTINGS_INVARIANT)
                .target
                .clone(),
            gateway: s.gateway.as_ref().expect(SETTINGS_INVARIANT).target.clone(),
            docker_mode: docker_mode_from_wire(
                s.docker_mode.as_ref().expect(SETTINGS_INVARIANT).target,
            ),
            runner_script: setting_value_to_path(
                &s.runner_script.as_ref().expect(SETTINGS_INVARIANT).target,
            ),
            participate: s.participate.as_ref().expect(SETTINGS_INVARIANT).target,
        }
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

    // -- Settings: cheap reads for the engine's hot paths (admit(), image
    // pulls) — extract just the one field needed, no whole-snapshot clone.

    pub fn load_ceiling_current(&self) -> f64 {
        settings_of(&self.tx.borrow())
            .load_ceiling
            .as_ref()
            .expect(SETTINGS_INVARIANT)
            .current
    }

    pub fn mem_floor_mib_current(&self) -> u64 {
        settings_of(&self.tx.borrow())
            .mem_floor_mib
            .as_ref()
            .expect(SETTINGS_INVARIANT)
            .current
    }

    pub fn linux_runner_image_current(&self) -> String {
        settings_of(&self.tx.borrow())
            .linux_runner_image
            .as_ref()
            .expect(SETTINGS_INVARIANT)
            .current
            .clone()
    }

    /// The desired image — what `FleetImageService.Prepare` verifies and
    /// then promotes to `current`.
    pub fn linux_runner_image_target(&self) -> String {
        settings_of(&self.tx.borrow())
            .linux_runner_image
            .as_ref()
            .expect(SETTINGS_INVARIANT)
            .target
            .clone()
    }

    /// The desired participation — what `AgentSupervisor`'s reconciler
    /// converges the attachment onto.
    pub fn participate_target(&self) -> bool {
        settings_of(&self.tx.borrow())
            .participate
            .as_ref()
            .expect(SETTINGS_INVARIANT)
            .target
    }

    /// The desired gateway — what `attach.rs` dials on its next attempt.
    /// There's no `gateway_current` reader: nothing needs to read back what
    /// was last dialed outside of the full `settings()`/`persisted_settings()`
    /// snapshots, which `GetSettings`/`Watch` already expose it through.
    pub fn gateway_target(&self) -> String {
        settings_of(&self.tx.borrow())
            .gateway
            .as_ref()
            .expect(SETTINGS_INVARIANT)
            .target
            .clone()
    }

    // -- Settings: writers. `load_ceiling`/`mem_floor_mib` apply instantly,
    // so their setters write both `current` and `target` in one
    // `send_modify` — there's never a moment where they should differ.
    //
    // `docker_mode`/`runner_script` are restart-scoped: `UpdateSettings`
    // moves only their `target`, and `current` stays whatever the process
    // started with (fixed by `AgentState::new` from the persisted seed)
    // until the next restart re-seeds from it — so they get a `target`
    // setter but no `current` setter. Whether an `Auto` docker_mode
    // actually found Docker is observable via `capabilities`, not by
    // resolving `current` away from the requested policy.
    //
    // `gateway`, `linux_runner_image`, and `participate` have independent
    // `current` setters, written only once the engine has realized the
    // value: `attach.rs` sets the gateway's `current` when it has actually
    // dialed that gateway, `FleetImageService.Prepare` sets the image's
    // `current` when the target has been pulled for every advertised arch
    // (startup's `init_docker` verifies the seed the same way, which is
    // why `AgentState::new` may seed `current == target`), and the
    // supervisor's participation reconciler flips `participate`'s
    // `current` when the detach/reattach completes.

    pub fn set_load_ceiling(&self, value: f64) {
        self.tx.send_modify(|s| {
            let setting = settings_mut(s)
                .load_ceiling
                .as_mut()
                .expect(SETTINGS_INVARIANT);
            setting.current = value;
            setting.target = value;
        });
    }

    pub fn set_mem_floor_mib(&self, value: u64) {
        self.tx.send_modify(|s| {
            let setting = settings_mut(s)
                .mem_floor_mib
                .as_mut()
                .expect(SETTINGS_INVARIANT);
            setting.current = value;
            setting.target = value;
        });
    }

    pub fn set_linux_runner_image_target(&self, value: &str) {
        self.tx.send_modify(|s| {
            value.clone_into(
                &mut settings_mut(s)
                    .linux_runner_image
                    .as_mut()
                    .expect(SETTINGS_INVARIANT)
                    .target,
            );
        });
    }

    pub fn set_linux_runner_image_current(&self, value: &str) {
        self.tx.send_modify(|s| {
            value.clone_into(
                &mut settings_mut(s)
                    .linux_runner_image
                    .as_mut()
                    .expect(SETTINGS_INVARIANT)
                    .current,
            );
        });
    }

    pub fn set_gateway_target(&self, value: &str) {
        self.tx.send_modify(|s| {
            value.clone_into(
                &mut settings_mut(s)
                    .gateway
                    .as_mut()
                    .expect(SETTINGS_INVARIANT)
                    .target,
            );
        });
    }

    /// Set `gateway.target` iff the enrollment snapshot at the moment of
    /// the write is `Unenrolled`. Both the check and the write happen
    /// inside the same `send_modify` closure, so a concurrent
    /// [`Self::set_enrollment`] (which uses the same watch sender) cannot
    /// interleave between them.
    ///
    /// This is what closes the race that a plain
    /// `validate() ... set_gateway_target(...)` pair leaks: an `Enroll`
    /// entering its round-trip flips enrollment to `Attaching` between
    /// validate's read and the write, and by the time the write lands the
    /// credential would be persisted under one gateway while the settings
    /// wrote the other. Returns the observed enrollment on refusal.
    pub fn try_set_gateway_target(&self, value: &str) -> Result<(), Enrollment> {
        let mut observed: Result<(), Enrollment> = Ok(());
        self.tx.send_modify(|s| {
            let enrollment = Enrollment::try_from(s.enrollment).unwrap_or(Enrollment::Unenrolled);
            if enrollment != Enrollment::Unenrolled {
                observed = Err(enrollment);
                return;
            }
            value.clone_into(
                &mut settings_mut(s)
                    .gateway
                    .as_mut()
                    .expect(SETTINGS_INVARIANT)
                    .target,
            );
        });
        observed
    }

    pub fn set_gateway_current(&self, value: &str) {
        self.tx.send_modify(|s| {
            value.clone_into(
                &mut settings_mut(s)
                    .gateway
                    .as_mut()
                    .expect(SETTINGS_INVARIANT)
                    .current,
            );
        });
    }

    pub fn set_docker_mode_target(&self, mode: DockerMode) {
        let mode = docker_mode_to_control(mode) as i32;
        self.tx.send_modify(|s| {
            settings_mut(s)
                .docker_mode
                .as_mut()
                .expect(SETTINGS_INVARIANT)
                .target = mode;
        });
    }

    pub fn set_runner_script_target(&self, script: Option<&Path>) {
        let value = path_to_setting_value(script);
        self.tx.send_modify(|s| {
            settings_mut(s)
                .runner_script
                .as_mut()
                .expect(SETTINGS_INVARIANT)
                .target = value;
        });
    }

    pub fn set_participate_target(&self, value: bool) {
        self.tx.send_modify(|s| {
            settings_mut(s)
                .participate
                .as_mut()
                .expect(SETTINGS_INVARIANT)
                .target = value;
        });
    }

    pub fn set_participate_current(&self, value: bool) {
        self.tx.send_modify(|s| {
            settings_mut(s)
                .participate
                .as_mut()
                .expect(SETTINGS_INVARIANT)
                .current = value;
        });
    }
}

#[cfg(test)]
#[allow(
    clippy::float_cmp,
    reason = "settings values are moved/copied here, never computed, so exact \
              float equality is always well-defined — no rounding can occur"
)]
mod tests {
    use super::*;

    fn seed() -> PersistedSettings {
        PersistedSettings {
            load_ceiling: 0.9,
            mem_floor_mib: 2048,
            linux_runner_image: "ghcr.io/actions/actions-runner:latest".to_owned(),
            gateway: "https://fleet.arcbox.dev".to_owned(),
            docker_mode: DockerMode::Auto,
            runner_script: None,
            participate: true,
        }
    }

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
        let snap = AgentState::new(&seed()).current();
        assert_eq!(snap.enrollment, Enrollment::Unenrolled as i32);
        assert_eq!(snap.machine_id, "");
        assert!(!snap.draining);
        assert!(snap.capabilities.is_empty());
        assert!(snap.in_flight.is_empty());
        assert!(snap.recent_verdicts.is_empty());
        assert!(snap.telemetry.is_none());
    }

    /// `AgentState` has no `gateway_current` reader (nothing outside tests
    /// needs it — see its doc comment), so tests read it via the full
    /// `settings()` snapshot instead.
    fn gateway_current(state: &AgentState) -> String {
        state.settings().gateway.unwrap().current
    }

    /// A freshly-seeded agent must report `current == target` for *every*
    /// setting, so a client's "current != target ⇒ pending" rendering shows
    /// nothing pending on a clean start. `docker_mode` is the load-bearing
    /// case: the seed here is `Auto`, and nothing at startup may resolve its
    /// `current` to a concrete `Enabled`/`Disabled` (which would leave it
    /// perpetually != the `Auto` target) — that resolution is observable via
    /// `capabilities`, not by moving `current` off the requested policy.
    #[test]
    fn settings_seed_current_equals_target() {
        let state = AgentState::new(&seed());
        assert_eq!(state.load_ceiling_current(), 0.9);
        assert_eq!(state.mem_floor_mib_current(), 2048);
        let settings = state.settings();
        let load_ceiling = settings.load_ceiling.unwrap();
        assert_eq!(load_ceiling.current, load_ceiling.target);
        let mem_floor = settings.mem_floor_mib.unwrap();
        assert_eq!(mem_floor.current, mem_floor.target);
        let linux_runner_image = settings.linux_runner_image.unwrap();
        assert_eq!(linux_runner_image.current, linux_runner_image.target);
        let gateway = settings.gateway.unwrap();
        assert_eq!(gateway.current, gateway.target);
        let docker_mode = settings.docker_mode.unwrap();
        assert_eq!(
            docker_mode.current,
            arcbox_fleet_control_proto::v1::DockerMode::Auto as i32
        );
        assert_eq!(docker_mode.current, docker_mode.target);
        let runner_script = settings.runner_script.unwrap();
        assert_eq!(runner_script.current, runner_script.target);
    }

    #[test]
    fn gateway_current_and_target_are_independent() {
        let state = AgentState::new(&seed());
        state.set_gateway_target("https://staging.fleet.arcbox.dev");
        assert_eq!(gateway_current(&state), "https://fleet.arcbox.dev");
        assert_eq!(state.gateway_target(), "https://staging.fleet.arcbox.dev");

        state.set_gateway_current("https://staging.fleet.arcbox.dev");
        assert_eq!(gateway_current(&state), state.gateway_target());
    }

    /// The atomic setter that closes the `settings::validate` race: it must
    /// accept a write while `Unenrolled` and refuse (leaving the target
    /// unchanged) for every non-`Unenrolled` enrollment. The check and the
    /// write both happen inside one `send_modify`, so a concurrent
    /// `set_enrollment` cannot slip between them.
    #[test]
    fn try_set_gateway_target_gates_on_enrollment() {
        let state = AgentState::new(&seed());
        assert!(
            state
                .try_set_gateway_target("https://staging.fleet.arcbox.dev")
                .is_ok()
        );
        assert_eq!(state.gateway_target(), "https://staging.fleet.arcbox.dev");

        for enrollment in [
            Enrollment::Attaching,
            Enrollment::Attached,
            Enrollment::Detached,
            Enrollment::CredentialRejected,
        ] {
            state.set_enrollment(enrollment, "fltm_test");
            assert_eq!(
                state.try_set_gateway_target("https://other.gateway.test"),
                Err(enrollment)
            );
            assert_eq!(
                state.gateway_target(),
                "https://staging.fleet.arcbox.dev",
                "{enrollment:?}: refused write must not mutate the target"
            );
        }
    }

    #[test]
    fn linux_runner_image_current_and_target_are_independent() {
        let state = AgentState::new(&seed());
        state.set_linux_runner_image_target("ghcr.io/acme/runner:v2");
        assert_eq!(
            state.linux_runner_image_current(),
            "ghcr.io/actions/actions-runner:latest"
        );
        assert_eq!(state.linux_runner_image_target(), "ghcr.io/acme/runner:v2");

        state.set_linux_runner_image_current("ghcr.io/acme/runner:v2");
        assert_eq!(
            state.linux_runner_image_current(),
            state.linux_runner_image_target()
        );
    }

    #[test]
    fn set_load_ceiling_sets_both_current_and_target() {
        let state = AgentState::new(&seed());
        state.set_load_ceiling(0.5);
        assert_eq!(state.load_ceiling_current(), 0.5);
        assert_eq!(state.settings().load_ceiling.unwrap().target, 0.5);
    }

    #[test]
    fn in_flight_add_and_remove_round_trips() {
        let state = AgentState::new(&seed());
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
        let state = AgentState::new(&seed());
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
        let state = AgentState::new(&seed());
        state.set_enrollment(Enrollment::Attaching, "fltm_test");
        let snap = state.current();
        assert_eq!(snap.enrollment, Enrollment::Attaching as i32);
        assert_eq!(snap.machine_id, "fltm_test");
    }

    #[test]
    fn set_draining_toggles() {
        let state = AgentState::new(&seed());
        state.set_draining(true);
        assert!(state.current().draining);
        state.set_draining(false);
        assert!(!state.current().draining);
    }
}
