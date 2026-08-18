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
    use arcbox_vm_driver::ShutdownMode;

    use crate::lifecycle::tasks::release::release_runtime_resources;

    use super::*;
    use crate::snapshot_cow::{CowOptions, CowTestProbe};
    use arcbox_vm_driver::testkit::FakeNetwork;
    use std::os::unix::fs::PermissionsExt;

    fn instance(id: &str) -> Arc<Mutex<ComputerRuntime>> {
        Arc::new(Mutex::new(ComputerRuntime::new(
            id.to_owned(),
            SandboxSpec::default(),
            None,
            PathBuf::from("/tmp/x"),
        )))
    }

    /// A sandbox this process adopted rather than booted holds a handle and
    /// no `PreparedVm`, and Remove must still reach its VMM: the old code
    /// took the `None` arm, cleared the handle, and reported success while
    /// Firecracker kept running — after which the dm device and TAP were
    /// torn out from under a live guest.
    #[tokio::test]
    async fn removing_an_adopted_sandbox_kills_its_vm_through_the_handle() {
        let data_dir = tempfile::tempdir().unwrap();
        let (manager, driver, probe) =
            super::super::testing::fake_manager_direct(data_dir.path()).await;
        let recorder = std::sync::OnceLock::new();
        let (runtime, _handle) =
            super::super::testing::live_sandbox_with(&manager, &driver, "adopted", |inner| {
                let (recording, handle) = super::super::testing::RecordsShutdown::wrap(inner);
                let _ = recorder.set(recording);
                handle
            })
            .await;
        // What the startup sweep hands back: the VM's handle, and no grip on
        // the process — nothing returns a `PreparedVm` across a restart.
        runtime.lock().unwrap().prepared = None;

        manager
            .remove_sandbox(&"adopted".to_owned(), false)
            .await
            .unwrap();

        assert_eq!(
            recorder.get().unwrap().modes(),
            vec![ShutdownMode::Kill],
            "the adopted vm is killed through its own handle"
        );
        let runtime = runtime.lock().unwrap();
        assert!(runtime.handle.is_none(), "the dead VM's handle is dropped");
        assert!(runtime.cow_handle.is_none(), "the CoW overlay is released");
        assert!(runtime.network.is_none(), "the network lease is released");
        assert_eq!(probe.teardown_count(), 1);
    }

    /// A computer the startup sweep took back must be usable, not merely
    /// listed: it runs no flow in this process, so nothing publishes the
    /// agent the exec path reads unless the seeding does.
    ///
    /// The unit-scale half of the CORE-135 acceptance test, which proves the
    /// same thing across a real process boundary.
    #[tokio::test]
    async fn an_adopted_computer_serves_an_exec() {
        let data_dir = tempfile::tempdir().unwrap();
        let (manager, driver, _probe, agents) =
            super::super::testing::fake_manager_with_agent(data_dir.path(), None).await;
        agents.on(
            &["echo", "still here"],
            crate::testkit::agent::Reply::stdout(b"still here".to_vec()),
        );
        super::super::testing::live_sandbox(&manager, &driver, "adopted").await;

        let mut output = manager
            .run_in_sandbox(
                &"adopted".to_owned(),
                vec!["echo".into(), "still here".into()],
                HashMap::new(),
                String::new(),
                String::new(),
                false,
                None,
                0,
            )
            .await
            .expect("an adopted computer is dialable");
        let mut stdout = Vec::new();
        while let Some(chunk) = output.recv().await {
            if let crate::agent::OutputChunk::Stdout(data) = chunk.unwrap() {
                stdout.extend_from_slice(&data);
            }
        }
        assert_eq!(stdout, b"still here");
    }

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
        let manager = SandboxManager::with_environment(
            config.clone(),
            crate::SandboxEnvironment {
                cow_manager: Some(Arc::new(
                    CowManager::new_with_test_probe(
                        CowOptions::new(&config.firecracker.data_dir),
                        Arc::clone(&cow_probe),
                    )
                    .unwrap(),
                )),
                ..crate::SandboxEnvironment::default()
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

    #[tokio::test]
    async fn release_removes_the_chroot_of_an_adopted_pool_slot() {
        let data_dir = tempfile::tempdir().unwrap();
        let chroot_base = data_dir.path().join("jailer");
        let mut config = VmmConfig::default();
        config.firecracker.data_dir = data_dir.path().to_string_lossy().into_owned();
        config.firecracker.jailer = Some(crate::config::JailerConfig {
            binary: "/usr/bin/jailer".into(),
            uid: 0,
            gid: 0,
            chroot_base_dir: Some(chroot_base.to_string_lossy().into_owned()),
            netns: None,
            new_pid_ns: false,
            cgroup_version: None,
            parent_cgroup: None,
            resource_limits: vec![],
        });
        let slot_chroot = chroot_root(&config.firecracker.binary, &chroot_base, "pool-slot");
        let sandbox_chroot = chroot_root(&config.firecracker.binary, &chroot_base, "job");
        std::fs::create_dir_all(&slot_chroot).unwrap();
        std::fs::create_dir_all(&sandbox_chroot).unwrap();

        let arc = instance("job");
        arc.lock().unwrap().pool_slot_id = Some("pool-slot".into());
        let config = Arc::new(config);
        let network: Arc<dyn GuestNetwork> = Arc::new(FakeNetwork::new());
        let cow_manager =
            Arc::new(CowManager::new(CowOptions::new(&config.firecracker.data_dir)).unwrap());

        release_runtime_resources("job", &arc, &network, &config, &cow_manager)
            .await
            .unwrap();

        assert!(!slot_chroot.parent().unwrap().exists());
        assert!(
            sandbox_chroot.exists(),
            "the sandbox-id chroot belongs to nobody here and must not be touched"
        );
    }
}
