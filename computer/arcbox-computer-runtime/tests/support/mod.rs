//! A manager over the fakes, and the waits its flows need.
//!
//! Every port this crate has is faked here — the VM driver
//! (`arcbox_vm_driver::testkit::FakeDriver`), the guest network
//! (`FakeNetwork`), the guest agent
//! ([`FakeAgentFactory`](arcbox_computer_runtime::testkit::agent::FakeAgentFactory))
//! and the copy-on-write rootfs (`CowTestProbe`) — so the real create →
//! boot → gate → ready → exec → pause → resume → checkpoint → restore →
//! expire → remove paths run on any host with no KVM, no root and no
//! Firecracker.
//!
//! What is *not* faked is the manager: these tests reach it only through
//! its public API, so nothing here can put a computer in a state a real
//! flow does not produce.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arcbox_computer_runtime::config::{JailerConfig, RuntimeConfig};
use arcbox_computer_runtime::testkit::agent::FakeAgentFactory;
use arcbox_computer_runtime::testkit::fake_environment;
use arcbox_computer_runtime::{
    NodeEnvironment, OutputChunk, SandboxEvent, SandboxId, SandboxManager, SandboxSpec,
    SandboxState,
};
use arcbox_vm_driver::testkit::{FakeDriver, FakeNetwork};
use tokio::sync::broadcast;

/// How long a wait helper gives the actor before failing the test.
const DEADLINE: Duration = Duration::from_secs(10);

/// Where the fixtures' data directories go.
///
/// **Not** `std::env::temp_dir()`, and short on purpose rather than out of
/// tidiness. A sandbox id has to fit what AF_UNIX leaves of the jail's
/// socket paths, and macOS's per-user `$TMPDIR` (`/var/folders/../T/`)
/// spends ~50 bytes of that on its own — enough to take the budget to
/// zero, so every `create_sandbox` would be refused at id validation
/// before reaching anything it meant to exercise. A short root is also
/// what a real node's jail base is.
///
/// The ingress budget is now whatever the driver in use reports
/// (`VmDriver::id_budget`), and [`FakeDriver`] lays down no jail, so it
/// reports none and no id here is refused for its length. The short root
/// stays because that is a property of these fixtures, not of the fake: a
/// fixture pointed at a real `FcDriver` gets the budget back, and gets it
/// from this path.
const SHORT_TMP_ROOT: &str = "/tmp";

/// How a fixture's manager is configured.
pub struct Setup {
    jailer: bool,
    warm: bool,
}

impl Setup {
    /// Jailer isolation, which checkpoint, restore and pause all require.
    ///
    /// The jail runs as the current user: `uid`/`gid` reach `chown` on
    /// every staged file, and chowning to one's own ids is the one form an
    /// unprivileged process is allowed. `mknod` is not, so the rootfs
    /// staging takes its copy fallback — the same branch a node without
    /// device-mapper takes.
    #[must_use]
    pub const fn jailed() -> Self {
        Self {
            jailer: true,
            warm: false,
        }
    }

    /// Direct mode, for the refusals that are *about* direct mode.
    #[must_use]
    pub const fn direct() -> Self {
        Self {
            jailer: false,
            warm: false,
        }
    }

    /// Serve eligible creates from warm snapshots, as a node does by
    /// default.
    ///
    /// Off in every other fixture on purpose: with it on, the second
    /// create of the same shape restores instead of booting, which is its
    /// own behaviour to test rather than a background condition to give
    /// every other test.
    #[must_use]
    pub const fn warm(mut self) -> Self {
        self.warm = true;
        self
    }

    /// Build the manager.
    pub async fn build(self) -> Fixture {
        let dir = tempfile::Builder::new()
            .prefix("abx")
            .tempdir_in(SHORT_TMP_ROOT)
            .expect("a short-pathed data dir");
        // Boot inputs the jail stages: real files, because the staging
        // helpers copy them. Their contents never reach a guest — the fake
        // driver boots from the spec, not from the image.
        std::fs::write(dir.path().join("k"), b"kernel").unwrap();
        std::fs::write(dir.path().join("r.ext4"), b"rootfs").unwrap();

        let mut config = RuntimeConfig::default();
        config.firecracker.data_dir = dir.path().to_string_lossy().into_owned();
        config.firecracker.warm_create = self.warm;
        // A node without device-mapper, said explicitly rather than left to
        // the host: an empty candidate list is how a config disables CoW,
        // and without it the answer would be "no dmsetup" on macOS and
        // "dmsetup, unprivileged" on a Linux runner — two different boot
        // paths for the same test. Every computer here therefore runs on a
        // copied rootfs, which is also the branch a pause has to take its
        // disk back out of the VM's area for.
        config.firecracker.dmsetup_candidates = Some(Vec::new());
        config.defaults.kernel = dir.path().join("k").to_string_lossy().into_owned();
        config.defaults.rootfs = dir.path().join("r.ext4").to_string_lossy().into_owned();
        config.firecracker.jailer = self.jailer.then(|| JailerConfig {
            uid: nix::unistd::geteuid().as_raw(),
            gid: nix::unistd::getegid().as_raw(),
            chroot_base_dir: Some(dir.path().join("j").to_string_lossy().into_owned()),
            netns: None,
            new_pid_ns: false,
            cgroup_version: None,
            parent_cgroup: None,
        });

        let ports = Ports {
            driver: FakeDriver::new(),
            agent: FakeAgentFactory::new(),
        };
        let manager = ports.manager(&config).await;
        Fixture {
            manager,
            ports,
            config,
            dir,
        }
    }
}

/// The faked ports, kept apart from the manager so a restart can hand the
/// same ones to its successor — which is what makes the guest a restart
/// adopts the same guest.
struct Ports {
    driver: FakeDriver,
    agent: FakeAgentFactory,
}

impl Ports {
    async fn manager(&self, config: &RuntimeConfig) -> Arc<SandboxManager> {
        let manager = SandboxManager::new(
            config.clone(),
            NodeEnvironment {
                // The fixture's own clones, so a restart hands its
                // successor the same ports; the startup cleanup is what
                // `fake_environment`'s network does not hold.
                driver: Arc::new(self.driver.clone()),
                network: Arc::new(FakeNetwork::with_startup_cleanup("test-boot")),
                agent: Arc::new(self.agent.clone()),
                ..fake_environment(config).expect("a copy-on-write manager over the data dir")
            },
        )
        .expect("the fakes offer every capability the manager requires")
        .into_shared();

        // Release the startup gate the guest network holds for a fresh
        // process, or no lease can be reserved. `startup_cleanup_token`
        // also awaits the orphan sweep, which every create gates on — and
        // the gate will not open until the addresses that sweep
        // quarantined have been handed back, which is the host's job.
        let token = manager
            .startup_cleanup_token()
            .await
            .unwrap()
            .expect("a fresh process owes a startup cleanup");
        settle_network_cleanups(&manager).await;
        manager.finalize_startup_cleanup(&token).await.unwrap();
        manager
    }
}

/// A manager over the fakes, with the handles a test scripts and asserts
/// through.
pub struct Fixture {
    pub manager: Arc<SandboxManager>,
    ports: Ports,
    config: RuntimeConfig,
    /// The data dir, kept alive for the fixture's life.
    dir: tempfile::TempDir,
}

impl Fixture {
    /// A jailed manager — what most flows need. See [`Setup`] for the rest.
    pub async fn jailed() -> Self {
        Setup::jailed().build().await
    }

    /// A direct-mode manager.
    pub async fn direct() -> Self {
        Setup::direct().build().await
    }

    /// The VM driver every computer here runs on.
    pub const fn driver(&self) -> &FakeDriver {
        &self.ports.driver
    }

    /// The guest agent every computer here answers through.
    pub const fn agent(&self) -> &FakeAgentFactory {
        &self.ports.agent
    }

    /// A computer's runtime directory.
    pub fn vm_dir(&self, id: &str) -> PathBuf {
        self.dir.path().join("sandboxes").join(id)
    }

    /// Stand a fresh manager up on the same data directory, the same
    /// driver and the same agent — what the next agent process sees.
    ///
    /// The caller decides what the departing one did first: `detach_all`
    /// leaves its guests running for the successor's sweep to adopt, and
    /// dropping without it kills them, which is the difference the two
    /// recovery paths turn on.
    pub async fn restart(self) -> Self {
        let Self {
            manager,
            ports,
            config,
            dir,
        } = self;
        // Dropped before the successor sweeps, not after: the registry the
        // manager owns holds every mailbox, so letting it go is what stops
        // the old actors and releases the VM handles they hold.
        drop(manager);
        // Those actors stop on their own tasks, and the successor's sweep
        // cannot adopt a VM its predecessor is still holding — so wait for
        // the handles to go rather than for a duration.
        let deadline = tokio::time::Instant::now() + DEADLINE;
        while !ports.driver.owned_vms().is_empty() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the departing process never let its VMs go: {:?}",
                ports.driver.owned_vms()
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let manager = ports.manager(&config).await;
        Self {
            manager,
            ports,
            config,
            dir,
        }
    }

    /// Create a computer and wait until it is `Ready` — the state every
    /// data-plane and lifecycle verb is specified against.
    pub async fn ready(&self, id: &str) -> SandboxId {
        let id = self
            .booted(SandboxSpec {
                id: Some(id.to_owned()),
                ..SandboxSpec::default()
            })
            .await;
        self.await_state(&id, SandboxState::Ready).await;
        id
    }

    /// Create a computer and wait for its READY *event*.
    ///
    /// Not the same as [`Self::ready`]: a spec carrying an initial `cmd`
    /// publishes READY and RUNNING in the same breath, so a computer whose
    /// cmd does not exit is announced ready and observed `Running`.
    pub async fn booted(&self, spec: SandboxSpec) -> SandboxId {
        let mut events = self.manager.subscribe_events();
        let (id, _ip) = self
            .manager
            .create_sandbox(spec)
            .await
            .expect("the create is accepted");
        await_action(&mut events, &id, action::READY).await;
        id
    }

    /// Wait until `id` reports `state`, or fail the test.
    ///
    /// Every verb answers from the computer's actor and several of them
    /// leave work running behind the answer, so a read taken right after
    /// one can still see the state it started from.
    pub async fn await_state(&self, id: &SandboxId, state: SandboxState) {
        let deadline = tokio::time::Instant::now() + DEADLINE;
        loop {
            let seen = self.manager.inspect_sandbox(id);
            match &seen {
                Ok(info) if info.state == state => return,
                _ if tokio::time::Instant::now() >= deadline => panic!(
                    "{id} never reached {state}: {}",
                    match seen {
                        Ok(info) => info.state.to_string(),
                        Err(error) => error.to_string(),
                    }
                ),
                _ => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    }

    /// Wait until `id` is no longer registered, or fail the test.
    pub async fn await_gone(&self, id: &SandboxId) {
        let deadline = tokio::time::Instant::now() + DEADLINE;
        while self.manager.inspect_sandbox(id).is_ok() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "{id} is still registered"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Play the host's half of the network-cleanup ticket protocol for
    /// every quarantined address, and answer with the ids it settled.
    ///
    /// A pause, stop or teardown quarantines the computer's address rather
    /// than freeing it: the host still holds forwarding state keyed by it,
    /// and only the host can say when that is gone. In the guest agent the
    /// answer arrives over `WatchSandboxCleanup`; here it is this call, and
    /// a resume that needs a fresh address blocks until it has been made.
    pub async fn settle_network_cleanups(&self) -> Vec<String> {
        settle_network_cleanups(&self.manager).await
    }

    /// Wait until `id` is `Failed` with its crash journal cleared, which
    /// is the last thing a release does and therefore the one observation
    /// that covers the whole of it.
    pub async fn await_released(&self, id: &SandboxId) {
        self.await_state(id, SandboxState::Failed).await;
        let journal = self.vm_dir(id).join("state.json");
        let deadline = tokio::time::Instant::now() + DEADLINE;
        while journal.exists() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "{id} kept its crash journal, so something it held was never released"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Run `cmd` in `id` and collect everything the guest wrote to stdout.
    pub async fn run(&self, id: &SandboxId, cmd: &[&str]) -> Vec<u8> {
        let mut output = self
            .manager
            .run_in_sandbox(
                id,
                cmd.iter().map(|arg| (*arg).to_owned()).collect(),
                HashMap::new(),
                String::new(),
                String::new(),
                false,
                None,
                0,
            )
            .await
            .expect("a Ready computer runs a workload");
        let mut stdout = Vec::new();
        while let Some(chunk) = output.recv().await {
            if let OutputChunk::Stdout(bytes) = chunk.expect("the output stream stays open") {
                stdout.extend_from_slice(&bytes);
            }
        }
        stdout
    }
}

/// Play the host's half of the network-cleanup ticket protocol for every
/// quarantined address, and answer with the ids it settled.
pub async fn settle_network_cleanups(manager: &SandboxManager) -> Vec<String> {
    let pending = manager.pending_network_cleanups().await.unwrap();
    for (id, token) in &pending {
        manager
            .validate_network_cleanup(id, token)
            .await
            .expect("the ledger validates its own ticket");
        manager
            .finalize_network_cleanup(id, token)
            .await
            .expect("the ticket recycles the address");
    }
    pending.into_iter().map(|(id, _)| id).collect()
}

/// The `action` values [`SandboxEvent`] carries, as the wire spells them.
///
/// Spelled out rather than imported: the constants they mirror are
/// crate-private, and it is the *strings* an out-of-crate consumer matches
/// on.
pub mod action {
    pub const CREATED: &str = "created";
    pub const READY: &str = "ready";
    pub const RUNNING: &str = "running";
    pub const IDLE: &str = "idle";
    pub const STOPPED: &str = "stopped";
    pub const FAILED: &str = "failed";
    pub const REMOVED: &str = "removed";
    pub const PAUSING: &str = "pausing";
    pub const PAUSED: &str = "paused";
    pub const RESUMED: &str = "resumed";
}

/// Wait for `action` on `id`, or fail the test — reporting a failure on
/// the same computer immediately rather than waiting out the deadline.
pub async fn await_action(
    events: &mut broadcast::Receiver<SandboxEvent>,
    id: &str,
    action: &str,
) -> SandboxEvent {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    loop {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .unwrap_or_else(|_| panic!("no {action} for {id} within the deadline"))
            .expect("the event stream stays open");
        if event.sandbox_id == id && event.action == action {
            return event;
        }
        assert_ne!(
            (event.action.as_str(), event.sandbox_id.as_str()),
            (self::action::FAILED, id),
            "{id} failed instead of reaching {action}: {:?}",
            event.attributes
        );
    }
}

/// Every `action` seen for `id` so far, in order.
pub fn drain_actions(events: &mut broadcast::Receiver<SandboxEvent>, id: &str) -> Vec<String> {
    let mut actions = Vec::new();
    while let Ok(event) = events.try_recv() {
        if event.sandbox_id == id {
            actions.push(event.action);
        }
    }
    actions
}

/// A spec whose initial command never exits, so the computer stays busy
/// until something tears it down.
pub fn never_exits(id: &str) -> SandboxSpec {
    SandboxSpec {
        id: Some(id.to_owned()),
        cmd: vec!["/bin/wedged".into()],
        ..SandboxSpec::default()
    }
}
