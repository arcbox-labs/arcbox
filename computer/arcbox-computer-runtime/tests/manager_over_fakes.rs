//! The manager's own flows, driven end to end over the fakes.
//!
//! One computer per test, created through `create_sandbox` and reached
//! only through the public API — so what these assert is what a caller
//! gets, and no test can reach a state a real flow does not produce.
//!
//! Runs anywhere: no KVM, no root, no Firecracker.
//!
//! What that buys, and what it does not. These computers are jailed and
//! run on a copied rootfs — the shape of a node without device-mapper —
//! so the staging, the pause that takes the disk back out of the VM's
//! area, and the resume that puts it back are the real ones. But the
//! *area* is the fake driver's `staged/` directory, and no fake removes a
//! jail: "a jail goes with the grip that owns its VMM" is the adapter's
//! rule, and only the fc-driver's own contract tests and the macOS
//! `sandbox` e2e can see it kept. Read a green run here as "the flows are
//! right", never as "nothing leaked".

mod support;

use std::collections::HashMap;

use arcbox_computer_runtime::testkit::agent::Reply;
use arcbox_computer_runtime::{
    IdleAction, LifecycleUpdate, RestoreSandboxSpec, SandboxSpec, SandboxState, VmmError,
    pause_reason,
};
use support::{Fixture, Setup, action, await_action, drain_actions, never_exits};

// ---------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------

/// The whole cold-boot path with no VMM: create, boot on the fake driver,
/// pass the readiness gate, run the initial cmd, reach READY — then exec
/// and move files through the port.
#[tokio::test]
async fn a_create_boots_to_ready_and_serves_exec_and_files() {
    let fixture = Fixture::jailed().await;
    fixture.agent().on(&["/bin/hello"], Reply::stdout(b"hi"));
    let mut events = fixture.manager.subscribe_events();

    let (id, ip) = fixture
        .manager
        .create_sandbox(SandboxSpec {
            id: Some("booted".into()),
            cmd: vec!["/bin/hello".into()],
            ..SandboxSpec::default()
        })
        .await
        .unwrap();
    assert!(
        !ip.is_empty(),
        "a networked create answers with its address"
    );
    await_action(&mut events, &id, action::READY).await;

    // The initial cmd ran through the reserved claim, and the guest clock
    // was set twice: once by the readiness probe this factory gates on,
    // once by the detached cold-boot sync (guests with no RTC wake at the
    // kernel epoch, so a boot that skips that is a real regression).
    assert!(
        fixture
            .agent()
            .started()
            .contains(&vec!["/bin/hello".to_owned()])
    );
    for _ in 0..100 {
        if fixture.agent().clock_syncs() >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        fixture.agent().clock_syncs(),
        2,
        "the readiness probe and the detached cold-boot sync, one each"
    );
    assert!(
        fixture.agent().net_reconfigs().is_empty(),
        "a cold boot re-addresses nothing"
    );

    // The file verbs reach the guest through the port.
    fixture
        .manager
        .write_sandbox_file(&id, "/tmp/note", 0o644, b"written")
        .await
        .unwrap();
    assert_eq!(
        fixture
            .manager
            .read_sandbox_file(&id, "/tmp/note")
            .await
            .unwrap(),
        b"written"
    );
    fixture
        .manager
        .move_sandbox_path(&id, "/tmp/note", "/tmp/moved")
        .await
        .unwrap();
    assert!(matches!(
        fixture.manager.stat_sandbox_path(&id, "/tmp/note").await,
        Err(VmmError::PathNotFound(_))
    ));

    // A watch is a stream the port owns rather than a socket, so what the
    // guest side emits arrives through it whatever the transport.
    let mut watch = fixture
        .manager
        .watch_sandbox_dir(&id, "/tmp/moved", false)
        .await
        .unwrap();
    fixture
        .agent()
        .emit_fs_event(&arcbox_computer_runtime::file_proto::FsEventDto {
            kind: arcbox_computer_runtime::file_proto::EVENT_MODIFIED.to_owned(),
            path: "/tmp/moved".to_owned(),
            renamed_to: String::new(),
        });
    assert_eq!(
        watch.next_event().await.unwrap().map(|event| event.path),
        Some("/tmp/moved".to_owned())
    );

    // And so does a workload, once the initial cmd has released the slot.
    fixture.await_state(&id, SandboxState::Ready).await;
    assert_eq!(fixture.run(&id, &["/bin/hello"]).await, b"hi");
}

/// The claim on the workload slot *is* the transition into Running, so a
/// cmd-carrying boot announces RUNNING before READY, and IDLE when the cmd
/// gives the slot back.
///
/// Where IDLE falls relative to READY is not fixed and must not be: the
/// gate finishing and the workload exiting are concurrent, which is why
/// the machine handles the exit in `gating` as well as in `running`.
#[tokio::test]
async fn a_cmd_carrying_boot_announces_its_workload_around_ready() {
    let fixture = Fixture::jailed().await;
    let mut events = fixture.manager.subscribe_events();

    let (id, _ip) = fixture
        .manager
        .create_sandbox(SandboxSpec {
            id: Some("noisy".into()),
            cmd: vec!["/bin/hello".into()],
            ..SandboxSpec::default()
        })
        .await
        .unwrap();
    fixture.await_state(&id, SandboxState::Ready).await;

    let actions = drain_actions(&mut events, &id);
    assert!(
        actions
            == [
                action::CREATED,
                action::RUNNING,
                action::READY,
                action::IDLE
            ]
            || actions
                == [
                    action::CREATED,
                    action::RUNNING,
                    action::IDLE,
                    action::READY
                ],
        "{actions:?}"
    );
}

/// A ready-probe command that never exits must end on the probe's own
/// budget, not park the boot forever. The host timeout is the only thing
/// that can end it — the guest's kill timer is the fake's to not have — so
/// this is exactly the path the double bound exists for.
#[tokio::test]
async fn a_ready_probe_command_that_never_exits_fails_the_boot() {
    let fixture = Fixture::jailed().await;
    fixture.agent().on(&["/bin/wedged"], Reply::NeverExits);
    let mut events = fixture.manager.subscribe_events();

    let (id, _ip) = fixture
        .manager
        .create_sandbox(SandboxSpec {
            id: Some("wedged".into()),
            ready_probe: Some(
                arcbox_computer_runtime::template_catalog::ReadyProbeSpec::Command {
                    cmd: vec!["/bin/wedged".into()],
                    timeout_seconds: 1,
                },
            ),
            ..SandboxSpec::default()
        })
        .await
        .unwrap();

    let failure = await_action(&mut events, &id, action::FAILED).await;
    assert!(
        failure.attributes["error"].contains("ready probe failed"),
        "unexpected failure: {:?}",
        failure.attributes
    );
}

/// The boot's own `cmd` can exit before its readiness gate finishes, and
/// the computer must still reach READY — and settle at `Ready`, not at
/// the `Running` its exited workload left behind.
#[tokio::test]
async fn a_boot_whose_cmd_exits_while_the_gate_runs_still_reaches_ready() {
    let fixture = Fixture::jailed().await;
    fixture.agent().on(&["/bin/cmd"], Reply::ok());
    // Fails at first, so the gate is still retrying when the cmd exits.
    fixture.agent().on(&["/bin/probe"], Reply::code(1));
    let mut events = fixture.manager.subscribe_events();

    let (id, _ip) = fixture
        .manager
        .create_sandbox(SandboxSpec {
            id: Some("gated".into()),
            cmd: vec!["/bin/cmd".into()],
            ready_probe: Some(
                arcbox_computer_runtime::template_catalog::ReadyProbeSpec::Command {
                    cmd: vec!["/bin/probe".into()],
                    timeout_seconds: 30,
                },
            ),
            ..SandboxSpec::default()
        })
        .await
        .unwrap();

    // Both have run: the workload exited inside the gate.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let started = fixture.agent().started();
        if started.iter().any(|cmd| cmd == &["/bin/cmd".to_owned()])
            && started.iter().any(|cmd| cmd == &["/bin/probe".to_owned()])
        {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "{started:?}");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    fixture.agent().on(&["/bin/probe"], Reply::ok());

    await_action(&mut events, &id, action::READY).await;
    fixture.await_state(&id, SandboxState::Ready).await;
    assert_eq!(fixture.run(&id, &["/bin/cmd"]).await, Vec::<u8>::new());
}

/// A boot the driver refuses fails the computer and gives back everything
/// the create had allocated — the address included, which is only visible
/// through the quarantine ledger.
#[tokio::test]
async fn a_boot_the_driver_refuses_fails_and_releases_the_computer() {
    let fixture = Fixture::jailed().await;
    fixture.driver().fail_next_boot();
    let mut events = fixture.manager.subscribe_events();

    let (id, _ip) = fixture
        .manager
        .create_sandbox(SandboxSpec {
            id: Some("doomed".into()),
            ..SandboxSpec::default()
        })
        .await
        .unwrap();

    await_action(&mut events, &id, action::FAILED).await;
    fixture.await_released(&id).await;
    assert_eq!(
        fixture.settle_network_cleanups().await,
        vec!["doomed".to_owned()],
        "the address is quarantined for host cleanup, not silently dropped"
    );
}

/// A create that fails between reserving an address and building its TAP
/// must hand the address back.
///
/// That window is real — the durable journal is written inside it, on
/// purpose, so no host resource exists before its cleanup metadata — and a
/// rollback that only knew about *activated* leases would strand the
/// address in the pool for the life of the process. Driven by planting a
/// directory where the journal's file goes.
#[tokio::test]
async fn a_create_that_fails_before_activation_hands_the_address_back() {
    let fixture = Fixture::jailed().await;
    std::fs::create_dir_all(fixture.vm_dir("doomed").join("state.json")).unwrap();

    fixture
        .manager
        .create_sandbox(SandboxSpec {
            id: Some("doomed".into()),
            ..SandboxSpec::default()
        })
        .await
        .expect_err("the journal write cannot succeed against a directory");

    // Nothing is quarantined — the lease never reached a TAP — and the
    // address is back in the pool for the next computer, which is only
    // visible in the address that one is given.
    assert!(
        fixture
            .manager
            .pending_network_cleanups()
            .await
            .unwrap()
            .is_empty()
    );
    let (_id, reused) = fixture
        .manager
        .create_sandbox(SandboxSpec {
            id: Some("next".into()),
            ..SandboxSpec::default()
        })
        .await
        .unwrap();
    assert_eq!(
        reused, "10.200.0.2",
        "the pool hands out its lowest free address, so a stranded lease shows up here"
    );
}

// ---------------------------------------------------------------------
// Deadlines
// ---------------------------------------------------------------------

/// The idle window opens on READY and the `Kill` policy destroys the
/// computer when it elapses.
#[tokio::test(start_paused = true)]
async fn an_idle_computer_is_removed_when_its_policy_says_kill() {
    let fixture = Fixture::jailed().await;
    let mut events = fixture.manager.subscribe_events();
    let id = fixture
        .booted(SandboxSpec {
            id: Some("bored".into()),
            idle_timeout_seconds: 2,
            on_idle: IdleAction::Kill,
            ..SandboxSpec::default()
        })
        .await;

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    await_action(&mut events, &id, action::REMOVED).await;
    fixture.await_gone(&id).await;
}

/// The `Pause` policy checkpoints instead of destroying, and says why: the
/// PAUSING event's reason is what tells a client an idle timer fired
/// rather than a caller asking.
#[tokio::test(start_paused = true)]
async fn an_idle_computer_pauses_and_says_the_timer_did_it() {
    let fixture = Fixture::jailed().await;
    let mut events = fixture.manager.subscribe_events();
    let id = fixture
        .booted(SandboxSpec {
            id: Some("napper".into()),
            idle_timeout_seconds: 2,
            on_idle: IdleAction::Pause,
            ..SandboxSpec::default()
        })
        .await;

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let pausing = await_action(&mut events, &id, action::PAUSING).await;
    assert_eq!(
        pausing.attributes.get("reason").map(String::as_str),
        Some(pause_reason::IDLE_TIMEOUT),
        "the PAUSING event names the idle timer, not a caller"
    );
    fixture.await_state(&id, SandboxState::Paused).await;
    assert!(
        fixture.manager.inspect_sandbox(&id).is_ok(),
        "the PAUSE policy never removes the computer"
    );
}

/// The TTL is a hard cap: it destroys the computer whatever it is doing,
/// which is what separates it from the idle timer, whose window a running
/// workload keeps shut.
#[tokio::test(start_paused = true)]
async fn a_ttl_expiry_removes_even_a_busy_computer() {
    let fixture = Fixture::jailed().await;
    fixture.agent().on(&["/bin/wedged"], Reply::NeverExits);
    let id = fixture.booted(never_exits("capped")).await;
    fixture.await_state(&id, SandboxState::Running).await;

    // Armed once the workload is running, so the cap cannot be spent on
    // the boot: under a paused clock every await advances virtual time.
    fixture
        .manager
        .set_sandbox_lifecycle(
            &id,
            LifecycleUpdate {
                ttl_seconds: Some(2),
                idle_timeout_seconds: Some(1),
                on_idle: Some(IdleAction::Kill),
            },
        )
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    fixture.await_gone(&id).await;
}

/// `SetLifecycle` re-arms the TTL from now and replaces the idle knobs it
/// names, leaving the ones it does not.
#[tokio::test]
async fn set_lifecycle_rearms_the_ttl_and_replaces_only_what_it_names() {
    let fixture = Fixture::jailed().await;
    let id = fixture.ready("knobs").await;

    let before = chrono::Utc::now();
    fixture
        .manager
        .set_sandbox_lifecycle(
            &id,
            LifecycleUpdate {
                ttl_seconds: Some(600),
                idle_timeout_seconds: Some(30),
                on_idle: Some(IdleAction::Pause),
            },
        )
        .await
        .unwrap();

    let info = fixture.manager.inspect_sandbox(&id).unwrap();
    let deadline = info.ttl_deadline.expect("ttl deadline armed");
    assert!(deadline >= before + chrono::Duration::seconds(600));
    assert!(deadline <= chrono::Utc::now() + chrono::Duration::seconds(600));
    assert_eq!(info.idle_timeout_seconds, 30);
    assert_eq!(info.on_idle, IdleAction::Pause);

    // Absent fields are unchanged; ttl 0 removes the cap.
    fixture
        .manager
        .set_sandbox_lifecycle(
            &id,
            LifecycleUpdate {
                ttl_seconds: Some(0),
                ..LifecycleUpdate::default()
            },
        )
        .await
        .unwrap();
    let info = fixture.manager.inspect_sandbox(&id).unwrap();
    assert_eq!(info.ttl_deadline, None);
    assert_eq!(info.idle_timeout_seconds, 30);
    assert_eq!(info.on_idle, IdleAction::Pause);
}

/// A lifecycle update needs a computer with a life left to shape.
#[tokio::test]
async fn set_lifecycle_rejects_terminal_states_and_missing_ids() {
    let fixture = Fixture::jailed().await;
    assert!(matches!(
        fixture
            .manager
            .set_sandbox_lifecycle(&"ghost".to_owned(), LifecycleUpdate::default())
            .await,
        Err(VmmError::NotFound(_))
    ));

    let stopped = fixture.ready("halted").await;
    let mut events = fixture.manager.subscribe_events();
    fixture.manager.stop_sandbox(&stopped, 1).await.unwrap();
    await_action(&mut events, &stopped, action::STOPPED).await;
    fixture.await_state(&stopped, SandboxState::Stopped).await;
    assert!(matches!(
        fixture
            .manager
            .set_sandbox_lifecycle(&stopped, LifecycleUpdate::default())
            .await,
        Err(VmmError::WrongState { .. })
    ));

    // Paused computers accept updates: the TTL keeps applying to them.
    let paused = fixture.ready("asleep").await;
    fixture.manager.pause_sandbox(&paused).await.unwrap();
    fixture.await_state(&paused, SandboxState::Paused).await;
    fixture
        .manager
        .set_sandbox_lifecycle(
            &paused,
            LifecycleUpdate {
                ttl_seconds: Some(120),
                ..LifecycleUpdate::default()
            },
        )
        .await
        .unwrap();
}

// ---------------------------------------------------------------------
// Pause / resume
// ---------------------------------------------------------------------

/// A pause has to record what it retained, or nothing can find it again:
/// the resume needs its checkpoint, and `Inspect`/`List` size the retained
/// state from the same fields.
#[tokio::test]
async fn a_pause_records_what_it_retained_and_a_resume_uses_it() {
    let fixture = Fixture::jailed().await;
    fixture.agent().on(&["/bin/hello"], Reply::stdout(b"hi"));
    let id = fixture.ready("nap").await;
    let mut events = fixture.manager.subscribe_events();

    fixture.manager.pause_sandbox(&id).await.unwrap();
    fixture.await_state(&id, SandboxState::Paused).await;
    let pausing = await_action(&mut events, &id, action::PAUSING).await;
    assert_eq!(
        pausing.attributes.get("reason").map(String::as_str),
        Some(pause_reason::PAUSE)
    );
    await_action(&mut events, &id, action::PAUSED).await;

    let info = fixture.manager.inspect_sandbox(&id).unwrap();
    assert!(info.paused_at.is_some(), "the pause records when it froze");
    assert!(
        info.storage_bytes > 0,
        "the retained checkpoint and disk are sized, not reported as nothing"
    );
    let listed = fixture
        .manager
        .list_sandboxes(None, &HashMap::new())
        .unwrap();
    let summary = listed.iter().find(|entry| entry.id == id).unwrap();
    assert_eq!(
        (summary.storage_bytes, summary.paused_at),
        (info.storage_bytes, info.paused_at),
        "List and Inspect resolve the same retained state differently and must agree"
    );

    // The pause checkpoint is lifecycle state, not a user checkpoint.
    assert!(
        fixture
            .manager
            .list_checkpoints(Some(&id))
            .unwrap()
            .is_empty(),
        "the internal pause checkpoint stays out of the catalog listing"
    );

    fixture.settle_network_cleanups().await;
    let ip = fixture
        .manager
        .resume_sandbox(&id, pause_reason::RESUME)
        .await
        .unwrap();
    assert!(!ip.is_empty(), "a resume answers with its fresh address");
    let resumed = await_action(&mut events, &id, action::RESUMED).await;
    assert_eq!(
        resumed.attributes.get("reason").map(String::as_str),
        Some(pause_reason::RESUME)
    );
    fixture.await_state(&id, SandboxState::Ready).await;
    assert_eq!(
        fixture.run(&id, &["/bin/hello"]).await,
        b"hi",
        "a resumed computer serves the data plane again"
    );
}

/// Pause is idempotent on `Paused` and refuses a busy computer.
#[tokio::test]
async fn pause_is_idempotent_and_gates_on_state() {
    let fixture = Fixture::jailed().await;
    fixture.agent().on(&["/bin/wedged"], Reply::NeverExits);

    assert!(matches!(
        fixture.manager.pause_sandbox(&"missing".to_owned()).await,
        Err(VmmError::NotFound(_))
    ));

    let asleep = fixture.ready("asleep").await;
    fixture.manager.pause_sandbox(&asleep).await.unwrap();
    fixture.await_state(&asleep, SandboxState::Paused).await;
    fixture
        .manager
        .pause_sandbox(&asleep)
        .await
        .expect("pausing a paused computer is a no-op");

    let busy = fixture.booted(never_exits("busy")).await;
    fixture.await_state(&busy, SandboxState::Running).await;
    assert!(matches!(
        fixture.manager.pause_sandbox(&busy).await,
        Err(VmmError::WrongState { .. })
    ));
}

/// Direct mode has no jail for a resume to restore into, so the refusal
/// comes before the pause touches anything.
#[tokio::test]
async fn a_direct_mode_pause_is_refused_before_it_freezes_anything() {
    let fixture = Fixture::direct().await;
    let id = fixture.ready("plain").await;

    let error = fixture.manager.pause_sandbox(&id).await.unwrap_err();
    assert!(matches!(error, VmmError::Config(_)), "{error}");
    assert!(error.to_string().contains("jailer"), "{error}");
    assert_eq!(
        fixture.manager.inspect_sandbox(&id).unwrap().state,
        SandboxState::Ready,
        "the refused pause left the computer alone"
    );
}

/// Resume is a no-op on a computer that is already live, and refuses one
/// that has nothing to resume from.
#[tokio::test]
async fn resume_is_a_noop_on_live_states_and_refuses_terminal_ones() {
    let fixture = Fixture::jailed().await;
    fixture.agent().on(&["/bin/wedged"], Reply::NeverExits);

    let ready = fixture.ready("awake").await;
    let address = fixture
        .manager
        .inspect_sandbox(&ready)
        .unwrap()
        .network
        .expect("a networked computer")
        .ip_address;
    assert_eq!(
        fixture
            .manager
            .resume_sandbox(&ready, pause_reason::RESUME)
            .await
            .unwrap(),
        address,
        "resuming a Ready computer answers with the address it already has"
    );

    let running = fixture.booted(never_exits("busy")).await;
    fixture.await_state(&running, SandboxState::Running).await;
    fixture
        .manager
        .resume_sandbox(&running, pause_reason::RESUME)
        .await
        .expect("resuming a busy computer is a no-op");

    let stopped = fixture.ready("halted").await;
    fixture.manager.stop_sandbox(&stopped, 1).await.unwrap();
    fixture.await_state(&stopped, SandboxState::Stopped).await;
    assert!(matches!(
        fixture
            .manager
            .resume_sandbox(&stopped, pause_reason::RESUME)
            .await,
        Err(VmmError::WrongState { .. })
    ));
}

/// A pause whose capture failed after freezing the guest cannot go back to
/// Ready — the port has no thaw — so it fails the computer the way a
/// failed boot does and releases everything it held.
#[tokio::test]
async fn a_pause_that_leaves_the_guest_frozen_fails_and_releases_the_computer() {
    let fixture = Fixture::jailed().await;
    let id = fixture.ready("frozen").await;
    fixture.driver().freeze_next_checkpoint();
    let mut events = fixture.manager.subscribe_events();

    let error = fixture.manager.pause_sandbox(&id).await.unwrap_err();
    assert!(
        !matches!(error, VmmError::WrongState { .. }),
        "the capture failure is the reported error: {error}"
    );
    fixture.await_released(&id).await;
    assert_eq!(
        drain_actions(&mut events, &id),
        [action::PAUSING, action::FAILED]
    );
    assert_eq!(
        fixture.settle_network_cleanups().await,
        vec![id.clone()],
        "a failed pause releases the address it held"
    );
    // Nothing to resume: the computer is Failed, not Paused.
    assert!(matches!(
        fixture
            .manager
            .resume_sandbox(&id, pause_reason::RESUME)
            .await,
        Err(VmmError::WrongState { .. })
    ));
}

/// The data-plane gates name a paused computer rather than reporting it
/// missing or wrongly-stated: a client's next move is Resume, and it needs
/// to be told so.
#[tokio::test]
async fn the_data_plane_reports_a_paused_computer_readably() {
    let fixture = Fixture::jailed().await;
    let id = fixture.ready("asleep").await;
    fixture.manager.pause_sandbox(&id).await.unwrap();
    fixture.await_state(&id, SandboxState::Paused).await;

    assert!(matches!(
        fixture.manager.read_sandbox_file(&id, "/tmp/x").await,
        Err(VmmError::Paused(paused)) if paused == id
    ));
    assert!(matches!(
        fixture
            .manager
            .run_in_sandbox(
                &id,
                vec!["/bin/anything".into()],
                HashMap::new(),
                String::new(),
                String::new(),
                false,
                None,
                0,
            )
            .await
            .err(),
        Some(VmmError::Paused(paused)) if paused == id
    ));
}

// ---------------------------------------------------------------------
// Checkpoint / restore
// ---------------------------------------------------------------------

/// A checkpoint clones the computer: the restore comes up Ready under a
/// new id, on a fresh address, serving the same guest.
#[tokio::test]
async fn a_checkpoint_restores_onto_a_fresh_address() {
    let fixture = Fixture::jailed().await;
    fixture.agent().on(&["/bin/hello"], Reply::stdout(b"hi"));
    let id = fixture.ready("origin").await;

    let checkpoint = fixture
        .manager
        .checkpoint_sandbox(&id, "user".into(), HashMap::new())
        .await
        .unwrap();
    assert_eq!(
        fixture
            .manager
            .list_checkpoints(Some(&id))
            .unwrap()
            .iter()
            .map(|entry| entry.id.clone())
            .collect::<Vec<_>>(),
        vec![checkpoint.snapshot_id.clone()]
    );
    assert_eq!(
        fixture.manager.inspect_sandbox(&id).unwrap().state,
        SandboxState::Ready,
        "the origin keeps running: the capture resumed it"
    );

    let (clone, clone_ip) = fixture
        .manager
        .restore_sandbox(RestoreSandboxSpec {
            id: Some("clone".into()),
            snapshot_id: checkpoint.snapshot_id.clone(),
            network_override: true,
            ..RestoreSandboxSpec::default()
        })
        .await
        .unwrap();
    fixture.await_state(&clone, SandboxState::Ready).await;
    assert_eq!(
        fixture.driver().restored_vms(),
        vec![arcbox_vm_driver::VmId::new(&clone).unwrap()],
        "the clone came from the checkpoint, not from a second boot"
    );
    assert_ne!(
        clone_ip,
        fixture
            .manager
            .inspect_sandbox(&id)
            .unwrap()
            .network
            .unwrap()
            .ip_address,
        "the clone is on an address of its own"
    );
    assert_eq!(fixture.run(&clone, &["/bin/hello"]).await, b"hi");
}

/// A capture that fails and leaves the guest running is an error the
/// caller can retry: the computer stays Ready with everything it holds.
#[tokio::test]
async fn a_recoverable_checkpoint_failure_leaves_the_computer_ready() {
    let fixture = Fixture::jailed().await;
    let id = fixture.ready("keeps").await;
    fixture.driver().fail_next_checkpoint();

    fixture
        .manager
        .checkpoint_sandbox(&id, "user".into(), HashMap::new())
        .await
        .expect_err("a capture the driver refused");

    assert_eq!(
        fixture.manager.inspect_sandbox(&id).unwrap().state,
        SandboxState::Ready
    );
    assert!(
        fixture
            .manager
            .pending_network_cleanups()
            .await
            .unwrap()
            .is_empty(),
        "the lease survives a failed capture"
    );
    assert_eq!(
        fixture.run(&id, &["/bin/anything"]).await,
        Vec::<u8>::new(),
        "the guest is still there"
    );
}

/// A capture whose guest stayed frozen — the driver's own resume failed —
/// has no way back: the Checkpoint RPC fails the computer the way a failed
/// boot does instead of leaving it Ready with a guest that never runs
/// again.
#[tokio::test]
async fn a_checkpoint_that_leaves_the_guest_frozen_fails_and_releases_the_computer() {
    let fixture = Fixture::jailed().await;
    let id = fixture.ready("frozen").await;
    fixture.driver().freeze_next_checkpoint();
    let mut events = fixture.manager.subscribe_events();

    let error = fixture
        .manager
        .checkpoint_sandbox(&id, "user".into(), HashMap::new())
        .await
        .expect_err("a capture that froze the guest");
    assert!(
        error.to_string().contains("could not be resumed"),
        "the driver's error is the reported one: {error}"
    );

    fixture.await_released(&id).await;
    assert_eq!(drain_actions(&mut events, &id), [action::FAILED]);
    assert_eq!(fixture.settle_network_cleanups().await, vec![id]);
}

/// A restore that fails before its commit must free the id before it
/// answers: the caller's next move is a cold boot under the same id, and
/// it would otherwise race the teardown into `AlreadyExists`.
#[tokio::test]
async fn a_failed_restore_frees_its_id_before_it_answers() {
    let fixture = Fixture::jailed().await;
    let origin = fixture.ready("origin").await;
    let checkpoint = fixture
        .manager
        .checkpoint_sandbox(&origin, "user".into(), HashMap::new())
        .await
        .unwrap();

    fixture.driver().fail_next_boot();
    fixture
        .manager
        .restore_sandbox(RestoreSandboxSpec {
            id: Some("second".into()),
            snapshot_id: checkpoint.snapshot_id.clone(),
            network_override: true,
            ..RestoreSandboxSpec::default()
        })
        .await
        .expect_err("the driver refused the restore");

    // The address the failed restore held is quarantined, as any teardown
    // leaves it; only the id is the restore's to free before it answers.
    fixture.settle_network_cleanups().await;
    let (again, _ip) = fixture
        .manager
        .restore_sandbox(RestoreSandboxSpec {
            id: Some("second".into()),
            snapshot_id: checkpoint.snapshot_id,
            network_override: true,
            ..RestoreSandboxSpec::default()
        })
        .await
        .expect("the failed restore left nothing owning the id");
    fixture.await_state(&again, SandboxState::Ready).await;
}

/// The names and labels the lifecycle machinery owns are not a caller's to
/// take: Remove deletes every snapshot carrying the pause name, and the
/// warm cache trusts its label as a lookup key.
#[tokio::test]
async fn a_caller_cannot_squat_on_the_reserved_checkpoint_name_or_labels() {
    let fixture = Fixture::jailed().await;
    let id = fixture.ready("origin").await;

    for (name, labels) in [
        ("arcbox-pause", HashMap::new()),
        (
            "ok",
            HashMap::from([("arcbox.warm_key".to_owned(), "mine".to_owned())]),
        ),
        (
            "ok",
            HashMap::from([("arcbox.template".to_owned(), "mine".to_owned())]),
        ),
    ] {
        let error = fixture
            .manager
            .checkpoint_sandbox(&id, name.to_owned(), labels)
            .await
            .expect_err("a reserved name or label is refused");
        assert!(matches!(error, VmmError::Config(_)), "{error}");
    }
}

/// A paused computer's checkpoint is lifecycle state, so Remove takes it
/// with the computer rather than leaving it in the catalog pinning the
/// rootfs it was captured from.
#[tokio::test]
async fn removing_a_paused_computer_takes_its_retained_checkpoint() {
    let fixture = Fixture::jailed().await;
    let id = fixture.ready("napper").await;
    assert!(
        fixture.manager.pinned_rootfs_paths().unwrap().is_empty(),
        "nothing is pinned before there is a checkpoint"
    );

    fixture.manager.pause_sandbox(&id).await.unwrap();
    fixture.await_state(&id, SandboxState::Paused).await;
    assert!(
        !fixture.manager.pinned_rootfs_paths().unwrap().is_empty(),
        "the pause checkpoint pins the rootfs it was captured from"
    );

    fixture.manager.remove_sandbox(&id, false).await.unwrap();
    fixture.await_gone(&id).await;
    assert!(
        fixture.manager.pinned_rootfs_paths().unwrap().is_empty(),
        "the retained checkpoint went with the computer"
    );
}

// ---------------------------------------------------------------------
// Warm create
// ---------------------------------------------------------------------

/// With warm create on, a cold boot publishes a snapshot of the idle guest
/// and the next create of the same shape restores it instead of booting a
/// kernel.
#[tokio::test]
async fn a_warm_create_publishes_a_snapshot_the_next_create_restores() {
    let fixture = Setup::jailed().warm().build().await;
    let first = fixture.ready("first").await;
    // The publish runs inside the boot's gate, so by READY it has landed.
    assert!(
        !fixture.manager.pinned_rootfs_paths().unwrap().is_empty(),
        "the warm snapshot pins the rootfs it was taken from"
    );
    assert!(
        fixture.driver().restored_vms().is_empty(),
        "the first create of a shape has nothing to restore from"
    );

    let second = fixture.ready("second").await;
    assert_ne!(first, second);
    // The whole point, and not visible from the state a caller reads: a
    // cold-booted second computer also reaches Ready under its own id.
    assert_eq!(
        fixture.driver().restored_vms(),
        vec![arcbox_vm_driver::VmId::new(&second).unwrap()],
        "the second create of the same shape restores instead of booting"
    );
}

/// A warm publish that leaves the guest frozen is the one publish failure
/// the boot cannot shrug off: the capture is best-effort, but a guest that
/// will never run again must not be announced READY.
#[tokio::test]
async fn a_boot_whose_warm_publish_freezes_the_guest_fails() {
    let fixture = Setup::jailed().warm().build().await;
    fixture.driver().freeze_next_checkpoint();
    let mut events = fixture.manager.subscribe_events();

    let (id, _ip) = fixture
        .manager
        .create_sandbox(SandboxSpec {
            id: Some("chilled".into()),
            ..SandboxSpec::default()
        })
        .await
        .unwrap();
    let failure = await_action(&mut events, &id, action::FAILED).await;
    assert!(
        failure.attributes["error"].contains("could not be resumed"),
        "unexpected failure: {:?}",
        failure.attributes
    );
}

// ---------------------------------------------------------------------
// Remove, stop, and the next process
// ---------------------------------------------------------------------

/// A forced Remove preempts a boot that is still in its readiness gate,
/// rather than waiting it out — and releases everything the half-built
/// computer had taken.
#[tokio::test]
async fn a_forced_remove_preempts_a_boot_in_flight() {
    let fixture = Fixture::jailed().await;
    fixture.agent().on(&["/bin/gate"], Reply::NeverExits);
    let mut events = fixture.manager.subscribe_events();

    let (id, _ip) = fixture
        .manager
        .create_sandbox(SandboxSpec {
            id: Some("wedged".into()),
            ready_probe: Some(
                arcbox_computer_runtime::template_catalog::ReadyProbeSpec::Command {
                    cmd: vec!["/bin/gate".into()],
                    // Long enough that a Remove waiting for the gate would
                    // blow this test's own deadline instead of preempting.
                    timeout_seconds: 600,
                },
            ),
            ..SandboxSpec::default()
        })
        .await
        .unwrap();
    await_action(&mut events, &id, action::CREATED).await;
    fixture.await_state(&id, SandboxState::Starting).await;

    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        fixture.manager.remove_sandbox(&id, true),
    )
    .await
    .expect("a forced remove must preempt the gate")
    .unwrap();

    fixture.await_gone(&id).await;
    assert!(!fixture.vm_dir("wedged").exists());
    assert_eq!(fixture.settle_network_cleanups().await, vec![id]);
}

/// A non-forced Remove refuses a computer that is still doing something;
/// the forced one is the escape hatch.
#[tokio::test]
async fn remove_refuses_a_busy_computer_unless_forced() {
    let fixture = Fixture::jailed().await;
    fixture.agent().on(&["/bin/wedged"], Reply::NeverExits);
    let id = fixture.booted(never_exits("busy")).await;
    fixture.await_state(&id, SandboxState::Running).await;
    let mut events = fixture.manager.subscribe_events();

    assert!(matches!(
        fixture.manager.remove_sandbox(&id, false).await,
        Err(VmmError::WrongState { .. })
    ));
    fixture.manager.remove_sandbox(&id, true).await.unwrap();
    await_action(&mut events, &id, action::REMOVED).await;
    fixture.await_gone(&id).await;
}

/// A graceful exit must leave the guests running, or the next process's
/// adoption is reachable only after a crash: the driver handle kills on
/// drop until it has been detached. What the successor takes back must
/// then be usable, not merely listed — it runs no flow in this process, so
/// nothing publishes the agent the exec path reads unless the seeding
/// does.
#[tokio::test]
async fn a_detached_computer_is_adopted_by_the_next_process_and_serves_an_exec() {
    let mut fixture = Fixture::jailed().await;
    fixture
        .agent()
        .on(&["echo", "still here"], Reply::stdout(b"still here"));
    let id = fixture.ready("keeper").await;

    fixture.manager.detach_all().await.unwrap();
    fixture = fixture.restart().await;

    fixture.await_state(&id, SandboxState::Ready).await;
    assert_eq!(
        fixture.run(&id, &["echo", "still here"]).await,
        b"still here",
        "an adopted computer is dialable"
    );

    // A computer this process adopted holds a handle and no grip on the
    // VMM process, and Remove must still reach its VM: an implementation
    // that only cleared the handle would report success while the VMM kept
    // running, after which the overlay and TAP are torn out from under a
    // live guest.
    let vm = arcbox_vm_driver::VmId::new(&id).unwrap();
    fixture.manager.remove_sandbox(&id, false).await.unwrap();
    fixture.await_gone(&id).await;
    assert_eq!(
        fixture.driver().shutdowns(&vm),
        vec![arcbox_vm_driver::ShutdownMode::Kill],
        "the adopted vm is killed through its own handle"
    );
}

/// An adopted computer running on a copied rootfs cannot be paused: its
/// disk lives in the VM's area, and this process holds no grip on that VM
/// to reach in with. The refusal is raised before the pause takes anything
/// out — the boundary R3 PR-G3 moves.
///
/// What the refusal costs is the part worth pinning. `release_for_pause`
/// declines before its own kill, but a release that fails has no
/// recoverable arm in `releasing` the way a failed *capture* does in
/// `capturing`, so the computer takes the shared failure path: killed
/// through its handle, released, durably `Failed`. A caller therefore
/// loses the computer to a pause that was refused for its safety — and
/// the kill it loses it to is the grip's completed kill, which on a real
/// adapter takes the jail, and in copy mode the rootfs inside it. Asserted
/// as it behaves, not as it should: the fix belongs with the routes G3
/// adds, and this is the test that will say when they arrive.
#[tokio::test]
async fn an_adopted_computer_on_a_copied_rootfs_refuses_to_pause() {
    let mut fixture = Fixture::jailed().await;
    let id = fixture.ready("handed-over").await;

    fixture.manager.detach_all().await.unwrap();
    fixture = fixture.restart().await;
    fixture.await_state(&id, SandboxState::Ready).await;

    let error = fixture.manager.pause_sandbox(&id).await.unwrap_err();
    assert!(matches!(error, VmmError::Unavailable(_)), "{error}");
    assert!(
        error.to_string().contains("cannot be taken out"),
        "the refusal names the route it does not have: {error}"
    );

    // Refused, and then torn down anyway.
    fixture.await_released(&id).await;
    assert_eq!(
        fixture
            .driver()
            .shutdowns(&arcbox_vm_driver::VmId::new(&id).unwrap()),
        vec![arcbox_vm_driver::ShutdownMode::Kill],
        "the guest the refusal was protecting is killed by the failure path"
    );
    assert_eq!(fixture.settle_network_cleanups().await, vec![id]);
}

/// A computer whose VMM did not survive the gap comes back `Failed`, not
/// silently `Ready`: its journal is all the successor has, and a record
/// interrupted in a live phase describes a guest that is no longer there.
#[tokio::test]
async fn a_computer_whose_vm_died_comes_back_failed() {
    let mut fixture = Fixture::jailed().await;
    let id = fixture.ready("orphan").await;

    // The process leaves and its VMM dies with it. The journal survives,
    // so the successor's sweep has something to classify and nothing to
    // adopt.
    fixture.manager.detach_all().await.unwrap();
    fixture
        .driver()
        .kill(&arcbox_vm_driver::VmId::new(&id).unwrap())
        .expect("the vm was still registered");
    fixture = fixture.restart().await;

    let info = fixture
        .manager
        .inspect_sandbox(&id)
        .expect("the sweep reinstated the computer");
    assert_eq!(info.state, SandboxState::Failed);
    fixture.manager.remove_sandbox(&id, false).await.unwrap();
    fixture.await_gone(&id).await;
}

// ---------------------------------------------------------------------
// Durable create replay
// ---------------------------------------------------------------------

/// A create retried under the same request key answers from the record
/// rather than building a second computer — the durable half of an
/// at-least-once RPC.
///
/// The replay is its own verb, and has to be: `create_sandbox_keyed`
/// claims the id in memory *before* it consults the durable record, so
/// while the computer is live the claim answers first. A caller that
/// retries has to ask the record.
#[tokio::test]
async fn a_create_replays_its_recorded_outcome_rather_than_building_a_second_computer() {
    let fixture = Fixture::jailed().await;
    let spec = SandboxSpec {
        id: Some("twice".into()),
        ..SandboxSpec::default()
    };
    let (id, ip) = fixture
        .manager
        .create_sandbox_keyed(spec.clone(), "one-key")
        .await
        .unwrap();
    fixture.await_state(&id, SandboxState::Ready).await;

    assert_eq!(
        fixture
            .manager
            .replay_sandbox_create(&id, "one-key")
            .await
            .unwrap(),
        Some((id.clone(), ip)),
        "the retry replays the recorded outcome"
    );
    assert_eq!(
        fixture
            .manager
            .replay_sandbox_create("nobody", "one-key")
            .await
            .unwrap(),
        None,
        "there is nothing to replay for an id no create ever recorded"
    );
    assert!(
        matches!(
            fixture
                .manager
                .replay_sandbox_create(&id, "another-key")
                .await,
            Err(VmmError::AlreadyExists(_))
        ),
        "the key that made the record owns it"
    );
    assert!(matches!(
        fixture.manager.create_sandbox_keyed(spec, "one-key").await,
        Err(VmmError::AlreadyExists(_))
    ));
    assert_eq!(
        fixture
            .manager
            .list_sandboxes(None, &HashMap::new())
            .unwrap()
            .len(),
        1,
        "no second computer was built"
    );
}

/// A create of a live id under a *different* key is a collision, not a
/// replay: the record's owner is the key that made it.
#[tokio::test]
async fn a_create_of_a_live_id_under_another_key_is_refused() {
    let fixture = Fixture::jailed().await;
    let spec = || SandboxSpec {
        id: Some("taken".into()),
        ..SandboxSpec::default()
    };
    let (id, _ip) = fixture
        .manager
        .create_sandbox_keyed(spec(), "mine")
        .await
        .unwrap();
    fixture.await_state(&id, SandboxState::Ready).await;

    assert!(matches!(
        fixture.manager.create_sandbox_keyed(spec(), "yours").await,
        Err(VmmError::AlreadyExists(_))
    ));

    // And a same-key retry after the computer has left its live phases is
    // refused too: its recorded outcome names an address it no longer has.
    fixture.manager.stop_sandbox(&id, 1).await.unwrap();
    fixture.await_state(&id, SandboxState::Stopped).await;
    assert!(matches!(
        fixture.manager.create_sandbox_keyed(spec(), "mine").await,
        Err(VmmError::AlreadyExists(_))
    ));
}
