//! The driver contract: what every adapter must do the same way.
//!
//! An adapter instantiates [`driver_contract!`](crate::driver_contract) in
//! its own (usually `#[ignore]`d, hardware-backed) test crate with a
//! [`ContractHarness`] that knows how to build a spec for that VMM and how
//! to tell when its guest is usable; the macro expands to one `#[tokio::test]`
//! per check below. [`FakeHarness`] is the reference harness, and the fake
//! passes the same checks (`tests/fake_contract.rs`).
//!
//! Each check is also a plain `pub async fn` here, so an adapter can run one
//! of them by hand under a custom setup.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;

use super::FakeDriver;
use crate::driver::{VmDriver, VmHandle};
use crate::spec::{
    BootSpec, CacheMode, ConsoleSpec, DiskSpec, MacAddr, NicAttachment, NicSpec, VmId, VmSpec,
    VsockSpec,
};

mod checks;

pub use checks::*;

/// What the contract needs from an adapter's test setup.
#[async_trait]
pub trait ContractHarness: Send + Sync {
    /// The driver under test.
    fn driver(&self) -> Arc<dyn VmDriver>;

    /// A bootable spec for `id` that asks for every device the driver
    /// claims a capability for (vsock, balloon, console, ...), so the
    /// capability agreement check sees each accessor at its `Some`.
    fn spec(&self, id: &VmId) -> VmSpec;

    /// A fresh, empty per-VM runtime directory; a new one on every call.
    fn runtime_dir(&self) -> PathBuf;

    /// A guest vsock port that answers a dial once the guest is ready, if
    /// the guest has one (an agent port). `None` skips the dial check.
    fn dial_port(&self) -> Option<u32>;

    /// The host-side vsock port a booted guest dials out to as soon as it is
    /// up (its READY announce), if it does that; [`ready`](Self::ready) must
    /// not return before that dial-out was made. `None` skips the
    /// prepared-listener check.
    fn guest_dial_out_port(&self) -> Option<u32>;

    /// Waits until the guest behind `handle` is usable. For the fake this
    /// is where the "guest" makes its dial-out.
    async fn ready(&self, handle: &dyn VmHandle);
}

/// The reference harness: [`FakeDriver`] over temporary directories.
pub struct FakeHarness {
    driver: Arc<FakeDriver>,
    root: tempfile::TempDir,
    dirs: AtomicUsize,
}

impl FakeHarness {
    /// A harness over `FakeDriver::new()`.
    pub fn new() -> Self {
        Self::with_driver(FakeDriver::new())
    }

    /// A harness over a configured fake — a reduced capability set, say.
    pub fn with_driver(driver: FakeDriver) -> Self {
        Self {
            driver: Arc::new(driver),
            root: tempfile::tempdir().expect("temporary directory for the fake harness"),
            dirs: AtomicUsize::new(0),
        }
    }

    /// The fake behind the harness, for pushing console bytes or guest
    /// connections.
    pub fn fake(&self) -> &FakeDriver {
        &self.driver
    }

    /// The port the fake "guest" dials out to from [`ContractHarness::ready`].
    pub const READY_PORT: u32 = 1025;
}

impl Default for FakeHarness {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ContractHarness for FakeHarness {
    fn driver(&self) -> Arc<dyn VmDriver> {
        self.driver.clone()
    }

    fn spec(&self, id: &VmId) -> VmSpec {
        VmSpec {
            id: id.clone(),
            cpus: 1,
            memory_mib: 128,
            boot: BootSpec::Kernel {
                image: self.file("vmlinux"),
                cmdline: "console=hvc0".into(),
                initrd: None,
            },
            disks: vec![DiskSpec {
                id: "rootfs".into(),
                path: self.file("rootfs.ext4"),
                read_only: false,
                root: true,
                cache: CacheMode::Unsafe,
            }],
            nics: vec![NicSpec {
                id: "eth0".into(),
                mac: MacAddr::new([0x02, 0xfa, 0xce, 0, 0, 1]),
                attachment: NicAttachment::Tap {
                    name: "tap0".into(),
                },
            }],
            vsock: Some(VsockSpec { guest_cid: 3 }),
            shares: vec![],
            console: ConsoleSpec::File(self.root.path().join(format!("{id}.console"))),
            balloon: true,
            entropy: true,
            dirty_tracking: true,
            isolation: Default::default(),
        }
    }

    fn runtime_dir(&self) -> PathBuf {
        let n = self.dirs.fetch_add(1, Ordering::Relaxed);
        let dir = self.root.path().join(format!("vm{n}"));
        std::fs::create_dir_all(&dir).expect("runtime dir under the harness root");
        dir
    }

    fn dial_port(&self) -> Option<u32> {
        Some(1024)
    }

    fn guest_dial_out_port(&self) -> Option<u32> {
        Some(Self::READY_PORT)
    }

    async fn ready(&self, handle: &dyn VmHandle) {
        // The fake guest announces itself the moment it is "up".
        self.driver
            .guest_dial(handle.id(), Self::READY_PORT)
            .expect("the fake guest dials out on boot");
    }
}

impl FakeHarness {
    /// A real (empty) file under the harness root, so a contract check that
    /// copies a disk for a restore, or stages the spec's own files, has
    /// something to copy.
    fn file(&self, name: &str) -> PathBuf {
        let path = self.root.path().join(name);
        if !path.exists() {
            std::fs::write(&path, b"").expect("disk file under the harness root");
        }
        path
    }
}

/// Instantiates the driver contract as a test module.
///
/// `driver_contract!(fc, FcHarness::new())` expands to `mod fc` holding one
/// `#[tokio::test]` per contract check; each test evaluates the harness
/// expression afresh and runs the check against it. The invoking crate
/// needs `tokio` (with `macros` and `rt`) as a dev-dependency.
#[macro_export]
macro_rules! driver_contract {
    ($mod:ident, $harness:expr) => {
        mod $mod {
            #[allow(
                unused_imports,
                reason = "the harness expression may or may not name items of the enclosing module"
            )]
            use super::*;

            $crate::__driver_contract_checks! {
                $harness;
                boot_reports_running_then_exits_on_kill,
                events_deliver_exit_exactly_once,
                capabilities_agree_with_accessors,
                checkpoint_resume_keeps_running,
                checkpoint_hold_quiesces,
                restore_yields_a_live_vm,
                detach_then_adopt_round_trip,
                vsock_dial_reaches_the_guest,
                foreign_checkpoint_is_refused,
                record_is_stable,
                prepare_then_boot_matches_boot,
                prepared_listener_is_live_before_boot,
                discard_kills_a_prepared_vm,
                restore_reattaches_disks,
                a_staged_spec_boots,
                a_staged_disk_can_be_taken_back_out,
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __driver_contract_checks {
    ($harness:expr; $($check:ident),* $(,)?) => {
        $(
            #[tokio::test]
            async fn $check() {
                let harness = $harness;
                $crate::testkit::contract::$check(&harness).await;
            }
        )*
    };
}
