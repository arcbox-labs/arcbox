//! The driver contract against a real Firecracker.
//!
//! Every check the port's `driver_contract!` runs against the fake runs
//! here against `FcDriver` — directly, and under the jailer when
//! `FC_JAILER` is set — from `arcbox_vm_driver::testkit::contract`, one
//! `#[ignore]`d test each. The list below mirrors `driver_contract!`; a
//! check added to the port is added here.
//!
//! ## Prerequisites
//!
//! | Variable    | Description                                                |
//! |-------------|------------------------------------------------------------|
//! | `FC_BINARY` | Path to the `firecracker` binary                           |
//! | `FC_KERNEL` | Path to the kernel image (`vmlinux`)                       |
//! | `FC_ROOTFS` | Path to a root filesystem with `vm-agent` at `/sbin/vm-agent` |
//! | `FC_JAILER` | Path to the `jailer` binary; enables the `jailer` module    |
//!
//! Tests without their variables return early. Both modes need `/dev/kvm`;
//! the jailer needs root.
//!
//! ## Running
//!
//! ```bash
//! sudo -E cargo test --test contract -p arcbox-fc-driver -- --include-ignored --test-threads=1
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use arcbox_fc_driver::{FcDriver, FcDriverConfig, jail};
use arcbox_vm_driver::testkit::ContractHarness;
use arcbox_vm_driver::{
    BootSpec, CacheMode, ConsoleSpec, DiskSpec, Error, IsolationSpec, VmDriver, VmHandle, VmId,
    VmSpec, VsockSpec,
};
use arcbox_vm_proto::exec::{AGENT_PORT, READY_PORT};
use async_trait::async_trait;

/// How long `ready` dial-polls the agent port before giving up.
const READY_DEADLINE: Duration = Duration::from_secs(60);

/// The Firecracker assets the environment names.
struct Assets {
    binary: PathBuf,
    kernel: PathBuf,
    rootfs: PathBuf,
}

impl Assets {
    fn from_env() -> Option<Self> {
        Some(Self {
            binary: std::env::var_os("FC_BINARY")?.into(),
            kernel: std::env::var_os("FC_KERNEL")?.into(),
            rootfs: std::env::var_os("FC_ROOTFS")?.into(),
        })
    }
}

/// `FcDriver` over temporary directories, in one isolation mode.
struct FcHarness {
    driver: Arc<FcDriver>,
    assets: Assets,
    isolation: IsolationSpec,
    root: tempfile::TempDir,
    dirs: AtomicUsize,
}

impl FcHarness {
    /// Firecracker run directly; `None` without the assets. No jailer, so
    /// the driver claims no checkpoints and the contract's checkpoint and
    /// restore checks skip themselves.
    fn direct() -> Option<Self> {
        Some(Self::new(Assets::from_env()?, None))
    }

    /// Firecracker under the jailer as uid/gid 0 (production's shape), the
    /// mode checkpoints and restores are possible in; `None` without the
    /// assets or `FC_JAILER`.
    fn jailer() -> Option<Self> {
        let jailer: PathBuf = std::env::var_os("FC_JAILER")?.into();
        Some(Self::new(Assets::from_env()?, Some(jailer)))
    }

    fn new(assets: Assets, jailer: Option<PathBuf>) -> Self {
        let root = tempfile::Builder::new()
            .prefix("fc-contract-")
            .tempdir()
            .expect("temporary directory for the harness");
        let mut config = FcDriverConfig::new(&assets.binary);
        config.log_level = Some("Error".into());
        config.no_seccomp = true;
        config.socket_timeout = Duration::from_secs(15);
        let isolation = match &jailer {
            Some(_) => IsolationSpec::Jailer {
                uid: 0,
                gid: 0,
                chroot_base: root.path().join("jail"),
                netns: None,
                new_pid_ns: false,
                cgroup: None,
            },
            None => IsolationSpec::None,
        };
        config.jailer_binary = jailer;
        Self {
            driver: Arc::new(FcDriver::new(config)),
            assets,
            isolation,
            root,
            dirs: AtomicUsize::new(0),
        }
    }

    /// A private, writable copy of the rootfs for `id`: next to the runtime
    /// dirs when running directly, inside the VM's jail (where the sandbox
    /// manager stages it, and where the driver passes it through as
    /// `/rootfs.ext4`) under the jailer.
    fn rootfs_for(&self, id: &VmId) -> PathBuf {
        let path = match &self.isolation {
            IsolationSpec::Jailer { chroot_base, .. } => {
                jail::chroot_root(&self.assets.binary, chroot_base, id.as_str()).join("rootfs.ext4")
            }
            _ => self.root.path().join(format!("{id}.ext4")),
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("rootfs parent");
        }
        std::fs::copy(&self.assets.rootfs, &path).expect("copy the rootfs for the vm");
        path
    }
}

#[async_trait]
impl ContractHarness for FcHarness {
    fn driver(&self) -> Arc<dyn VmDriver> {
        self.driver.clone()
    }

    fn spec(&self, id: &VmId) -> VmSpec {
        VmSpec {
            id: id.clone(),
            cpus: 1,
            memory_mib: 256,
            boot: BootSpec::Kernel {
                image: self.assets.kernel.clone(),
                cmdline: "console=ttyS0 reboot=k panic=1 pci=off init=/sbin/vm-agent".into(),
                initrd: None,
            },
            disks: vec![DiskSpec {
                id: "rootfs".into(),
                path: self.rootfs_for(id),
                read_only: false,
                root: true,
                cache: CacheMode::Unsafe,
            }],
            // No NIC: the contract exercises no network, and a TAP would
            // need root even in direct mode.
            nics: vec![],
            vsock: Some(VsockSpec { guest_cid: 3 }),
            shares: vec![],
            console: ConsoleSpec::Off,
            balloon: false,
            entropy: false,
            dirty_tracking: true,
            isolation: self.isolation.clone(),
        }
    }

    fn runtime_dir(&self) -> PathBuf {
        let n = self.dirs.fetch_add(1, Ordering::Relaxed);
        let dir = self.root.path().join(format!("vm{n}"));
        std::fs::create_dir_all(&dir).expect("runtime dir under the harness root");
        dir
    }

    fn dial_port(&self) -> Option<u32> {
        Some(AGENT_PORT)
    }

    fn guest_dial_out_port(&self) -> Option<u32> {
        Some(READY_PORT)
    }

    /// vm-agent is up once its exec port answers a dial; it dials the
    /// READY port right after bringing that listener up.
    async fn ready(&self, handle: &dyn VmHandle) {
        let vsock = handle.vsock().expect("the contract spec asks for vsock");
        let deadline = tokio::time::Instant::now() + READY_DEADLINE;
        loop {
            match vsock.dial(AGENT_PORT).await {
                Ok(_) => return,
                Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
                Err(e) => panic!("dial the agent port of {}: {e}", handle.id()),
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "vm-agent in {} did not come up within {READY_DEADLINE:?}",
                handle.id()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// `driver_contract!` with every test `#[ignore]`d and skipped when the
/// harness has no assets: the port's macro cannot ignore, and these need
/// KVM, a Firecracker, and a rootfs.
macro_rules! ignored_contract {
    ($mod:ident, $harness:expr; $($check:ident),* $(,)?) => {
        mod $mod {
            use super::*;
            $(
                #[tokio::test]
                #[ignore = "needs FC_BINARY, FC_KERNEL, FC_ROOTFS (and FC_JAILER for the jailer) plus /dev/kvm"]
                async fn $check() {
                    let Some(harness) = $harness else {
                        eprintln!("skipping: assets not configured");
                        return;
                    };
                    arcbox_vm_driver::testkit::contract::$check(&harness).await;
                }
            )*
        }
    };
}

macro_rules! contract_modes {
    ($($check:ident),* $(,)?) => {
        ignored_contract!(direct, FcHarness::direct(); $($check),*);
        ignored_contract!(jailer, FcHarness::jailer(); $($check),*);
    };
}

// Keep in step with `driver_contract!` in arcbox-vm-driver's testkit.
contract_modes! {
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
