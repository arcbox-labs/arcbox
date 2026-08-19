//! What is left of the manager's teardown once the computer's actor owns it.
//!
//! `remove_computer_impl` and its parts — the busy gate, the bounded wait on a
//! boot's resource handoff, the epoch-stamped expiry retry, the `Arc::ptr_eq`
//! generation guard — are the actor's now: `Effect::AbortInflight` plus the
//! machine's remove arms, tested in `crate::lifecycle::tests`. The release
//! bodies themselves live in `crate::lifecycle::tasks::release`.

#[allow(unused_imports, reason = "the teardown surface is test-only now")]
use super::*;

#[cfg(test)]
mod tests {
    use arcbox_vm_driver::testkit::FakeDriver;

    use super::*;
    use crate::snapshot_cow::{CowOptions, CowTestProbe};

    /// A forced Remove of a boot wedged with its resources already handed
    /// over must take both of them: the VMM the crash journal names, and
    /// the dm-snapshot overlay the guest was going to run on.
    ///
    /// The wedge is the driver's `boot` parking
    /// ([`FakeDriver::park_next_boot`]) — after the prepared VMM is
    /// journalled and the CoW staged, which is the window where a Remove
    /// can strand either. That the discard the release issues really ends
    /// a VMM process is the driver contract's
    /// (`discard_kills_a_prepared_vm`, run against Firecracker in
    /// `arcbox-fc-driver`'s `tests/contract.rs`); what this test owns is
    /// that the release issues it at all, and drops the overlay with it.
    #[tokio::test]
    async fn force_remove_tears_down_cow_after_blocked_boot() {
        let data_dir = tempfile::tempdir().unwrap();

        let mut config = RuntimeConfig::default();
        config.firecracker.data_dir = data_dir.path().to_string_lossy().into_owned();
        config.defaults.kernel = data_dir
            .path()
            .join("kernel")
            .to_string_lossy()
            .into_owned();
        config.defaults.rootfs = data_dir
            .path()
            .join("rootfs")
            .to_string_lossy()
            .into_owned();
        let cow_probe = Arc::new(CowTestProbe::default());
        let driver = FakeDriver::new();
        let manager = ComputerManager::new(
            config.clone(),
            crate::NodeEnvironment {
                driver: Arc::new(driver.clone()),
                cow_manager: Arc::new(
                    CowManager::new_with_test_probe(
                        CowOptions::new(&config.firecracker.data_dir),
                        Arc::clone(&cow_probe),
                    )
                    .unwrap(),
                ),
                ..crate::testkit::fake_environment(&config).unwrap()
            },
        )
        .unwrap();
        manager.await_reconcile().await.unwrap();

        let boot_parked = driver.park_next_boot();
        let (id, _) = manager
            .create_computer_keyed(
                ComputerSpec {
                    id: Some("job".into()),
                    network: ComputerNetworkSpec {
                        mode: "none".into(),
                    },
                    ..Default::default()
                },
                "create-key",
            )
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(5), boot_parked)
            .await
            .expect("boot must reach the parked driver call")
            .unwrap();
        assert_eq!(cow_probe.setup_count(), 1);
        // The crash journal is what a restart would reclaim this VMM
        // through, and it is written before the CoW is staged — so a
        // journalled pid plus a staged overlay is the state the removal has
        // to preempt without stranding either.
        let vm_dir = data_dir.path().join("sandboxes/job");
        let state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(vm_dir.join("state.json")).unwrap()).unwrap();
        assert!(state["pid"].as_u64().is_some(), "the vmm pid is journalled");

        tokio::time::timeout(Duration::from_secs(5), manager.remove_computer(&id, true))
            .await
            .expect("force removal must cancel the parked boot")
            .unwrap();

        assert_eq!(
            driver.discarded_processes(),
            [arcbox_vm_driver::VmId::new("job").unwrap()],
            "the journalled VMM must be discarded, not left to a restart"
        );
        assert_eq!(cow_probe.teardown_count(), 1);
        assert!(manager.records.load(&id).unwrap().is_none());
        assert!(!vm_dir.exists());
    }
}
