//! What is left of the manager's teardown once the computer's actor owns it.
//!
//! `remove_sandbox_impl` and its parts — the busy gate, the bounded wait on a
//! boot's resource handoff, the epoch-stamped expiry retry, the `Arc::ptr_eq`
//! generation guard — are the actor's now: `Effect::AbortInflight` plus the
//! machine's remove arms, tested in `crate::lifecycle::tests`. The release
//! bodies themselves live in `crate::lifecycle::tasks::release`.

#[allow(unused_imports, reason = "the teardown surface is test-only now")]
use super::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot_cow::{CowOptions, CowTestProbe};
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn force_remove_tears_down_cow_after_blocked_boot() {
        let data_dir = tempfile::tempdir().unwrap();

        let fake_firecracker = data_dir.path().join("fake-firecracker");
        std::fs::write(&fake_firecracker, b"#!/bin/sh\nexec /bin/sleep 3600\n").unwrap();
        std::fs::set_permissions(&fake_firecracker, std::fs::Permissions::from_mode(0o755))
            .unwrap();

        let mut config = VmmConfig::default();
        config.firecracker.binary = fake_firecracker.to_string_lossy().into_owned();
        config.firecracker.data_dir = data_dir.path().to_string_lossy().into_owned();
        config.firecracker.socket_timeout_secs = Some(5);
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
        // The real Firecracker driver, over the fake binary above: what
        // this test wedges is the SDK's first API request, which no fake
        // driver has.
        let manager = SandboxManager::new(
            config.clone(),
            crate::NodeEnvironment {
                driver: Arc::new(arcbox_fc_driver::FcDriver::new(
                    arcbox_fc_driver::FcDriverConfig::from(&config.firecracker),
                )),
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

        // Reconciliation must finish before the test creates runtime state;
        // otherwise the startup sweep correctly classifies it as an orphan.
        let vm_dir = data_dir.path().join("sandboxes/job");
        std::fs::create_dir_all(&vm_dir).unwrap();

        // The SDK removes a stale socket before spawning. Seed one so this
        // task can bind only after spawn has crossed that exact boundary.
        let socket_path = vm_dir.join("firecracker.sock");
        std::fs::write(&socket_path, b"stale").unwrap();
        let socket_path_for_server = socket_path.clone();
        let (boot_blocked_tx, boot_blocked_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            while socket_path_for_server.exists() {
                tokio::task::yield_now().await;
            }
            let listener = loop {
                match tokio::net::UnixListener::bind(&socket_path_for_server) {
                    Ok(listener) => break listener,
                    Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("bind fake Firecracker socket: {error}"),
                }
            };

            // First connection is the SDK's spawn probe. Hold the first API
            // request open to wedge boot after the resource handoff.
            drop(listener.accept().await.unwrap());
            let _request = listener.accept().await.unwrap();
            boot_blocked_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });

        let (id, _) = manager
            .create_sandbox_keyed(
                SandboxSpec {
                    id: Some("job".into()),
                    network: SandboxNetworkSpec {
                        mode: "none".into(),
                    },
                    ..Default::default()
                },
                "create-key",
            )
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(5), boot_blocked_rx)
            .await
            .expect("boot must reach the blocked API request")
            .unwrap();
        assert_eq!(cow_probe.setup_count(), 1);
        // The crash journal is what a restart would reclaim this VMM
        // through, and it is written before the CoW is staged — so a
        // journalled pid plus a staged overlay is the state the removal has
        // to preempt without stranding either.
        let state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(vm_dir.join("state.json")).unwrap()).unwrap();
        let pid = u32::try_from(state["pid"].as_u64().expect("the vmm pid is journalled")).unwrap();

        tokio::time::timeout(Duration::from_secs(5), manager.remove_sandbox(&id, true))
            .await
            .expect("force removal must cancel the blocked boot")
            .unwrap();

        #[allow(clippy::cast_possible_wrap, reason = "child pid fits platform pid_t")]
        let exited = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None);
        assert_eq!(exited, Err(nix::errno::Errno::ESRCH));
        assert_eq!(cow_probe.teardown_count(), 1);
        assert!(manager.records.load(&id).unwrap().is_none());
        assert!(!vm_dir.exists());

        server.abort();
    }
}
