use super::*;

/// Returns true when the process effective UID is 0.
/// TAP creation requires root on Linux; tests that call `allocate()` skip
/// when this returns false.
#[cfg(target_os = "linux")]
fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status").is_ok_and(|s| {
        s.lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2))
            .is_some_and(|uid| uid == "0")
    })
}

#[test]
fn test_allocate_sequential_ips() {
    #[cfg(target_os = "linux")]
    if !is_root() {
        eprintln!("SKIP test_allocate_sequential_ips — requires root (TAP creation)");
        return;
    }
    let mgr = TapNetwork::new("172.20.0.0/16", "172.20.0.1", vec![]).unwrap();
    let a1 = mgr.allocate("vm-1").unwrap();
    let a2 = mgr.allocate("vm-2").unwrap();
    assert_ne!(a1.ip_address, a2.ip_address);
}

#[test]
fn test_release_returns_ip_to_pool() {
    #[cfg(target_os = "linux")]
    if !is_root() {
        eprintln!("SKIP test_release_returns_ip_to_pool — requires root (TAP creation)");
        return;
    }
    let mgr = TapNetwork::new("172.20.0.0/16", "172.20.0.1", vec![]).unwrap();
    let a1 = mgr.allocate("vm-1").unwrap();
    let first_ip = a1.ip_address;
    mgr.release(&a1);
    let a2 = mgr.allocate("vm-1").unwrap();
    assert_eq!(a2.ip_address, first_ip);
}

#[test]
fn test_mac_deterministic() {
    assert_eq!(mac_from_vm_id("abc"), mac_from_vm_id("abc"));
    assert_ne!(mac_from_vm_id("abc"), mac_from_vm_id("xyz"));
}

#[test]
fn test_invalid_prefix_len_rejected() {
    assert!(TapNetwork::new("10.0.0.0/0", "10.0.0.1", vec![]).is_err());
    assert!(TapNetwork::new("10.0.0.0/31", "10.0.0.1", vec![]).is_err());
    assert!(TapNetwork::new("10.0.0.0/32", "10.0.0.1", vec![]).is_err());
    assert!(TapNetwork::new("10.0.0.0/24", "10.0.0.1", vec![]).is_ok());
}

#[test]
fn test_next_ip_respects_subnet_boundary() {
    #[cfg(target_os = "linux")]
    if !is_root() {
        eprintln!("SKIP test_next_ip_respects_subnet_boundary — requires root (TAP creation)");
        return;
    }
    // /30 has exactly 2 host addresses (.1 gateway, .2 first usable)
    let mgr = TapNetwork::new("10.0.0.0/30", "10.0.0.1", vec![]).unwrap();
    let a = mgr.allocate("vm-1").unwrap();
    assert_eq!(a.ip_address, "10.0.0.2".parse::<Ipv4Addr>().unwrap());
    // Pool is now exhausted
    assert!(mgr.allocate("vm-2").is_err());
}

#[test]
fn test_pool_exhaustion_on_slash29() {
    #[cfg(target_os = "linux")]
    if !is_root() {
        eprintln!("SKIP test_pool_exhaustion_on_slash29 — requires root (TAP creation)");
        return;
    }
    // /29 has 6 usable addresses; gateway takes offset 1, leaving 5 for VMs.
    let mgr = TapNetwork::new("10.0.0.0/29", "10.0.0.1", vec![]).unwrap();
    for i in 0..5 {
        mgr.allocate(&format!("vm-{i}")).unwrap();
    }
    assert!(mgr.allocate("vm-overflow").is_err());
}

#[test]
fn test_mac_unicast_and_locally_administered_bits() {
    let mac = mac_from_vm_id("test-vm").to_string();
    let first_byte = u8::from_str_radix(&mac[..2], 16).unwrap();
    // Bit 1 set → locally administered; bit 0 clear → unicast.
    assert_eq!(
        first_byte & 0x02,
        0x02,
        "locally administered bit must be set"
    );
    assert_eq!(first_byte & 0x01, 0x00, "multicast bit must be clear");
}

#[test]
fn test_tap_name_encodes_last_two_octets() {
    let ip: Ipv4Addr = "172.20.3.17".parse().unwrap();
    assert_eq!(tap_name_from_ip(ip), "vmtap3-17");

    let ip2: Ipv4Addr = "10.0.255.1".parse().unwrap();
    assert_eq!(tap_name_from_ip(ip2), "vmtap255-1");
}

/// Expose targeting must follow the datapath actually applied to the
/// TAP, and default to the fwmark form when the record is gone (agent
/// restart) — the eBPF links died with that process, so only the
/// iptables machinery could still be translating.
#[test]
fn expose_target_follows_the_applied_datapath() {
    let manager = TapNetwork::new("172.20.0.0/16", "172.20.0.1", vec![]).unwrap();
    // No activation record: an invariant TAP a previous process left.
    assert_eq!(
        manager.expose_target("vmtap0-2"),
        ExposeTarget::GuestIpWithFwmark
    );
    let record = |applied| {
        manager
            .applied
            .lock()
            .unwrap()
            .insert("vmtap0-2".to_owned(), applied)
    };
    record(AppliedDatapath::Ebpf);
    assert_eq!(manager.expose_target("vmtap0-2"), ExposeTarget::PoolIp);
    record(AppliedDatapath::Iptables);
    assert_eq!(
        manager.expose_target("vmtap0-2"),
        ExposeTarget::GuestIpWithFwmark
    );
    // A legacy guest owns the pool IP outright. Recorded at activation
    // rather than left absent, which is what keeps it distinguishable
    // from the leftover TAP above.
    record(AppliedDatapath::Untranslated);
    assert_eq!(manager.expose_target("vmtap0-2"), ExposeTarget::PoolIp);
}

/// A record naming any other TAP for its address is not one this pool
/// could have written, so adoption refuses it — and hands the address
/// back, since the owner answers a refusal by tearing the sandbox down.
#[test]
fn adopt_refuses_a_tap_name_this_pool_would_not_give() {
    let pool = || TapNetwork::new("10.0.99.0/24", "10.0.99.1", vec![]).unwrap();
    // What a previous process journaled, with the TAP name rewritten.
    let mut allocation = pool().reserve("box").unwrap();
    allocation.tap_name = "vmtap-elsewhere".into();

    let manager = pool();
    let error = manager
        .adopt("box", &allocation, AttachMode::Invariant)
        .unwrap_err();
    assert!(error.to_string().contains("vmtap-elsewhere"), "{error}");
    assert!(
        !manager
            .allocated
            .lock()
            .unwrap()
            .contains(&u32::from(allocation.ip_address)),
        "a refused adoption keeps no address"
    );

    // An id the port could never name (`..`) is refused before that.
    allocation.tap_name = tap_name_from_ip(allocation.ip_address);
    assert!(
        manager
            .adopt("..", &allocation, AttachMode::Invariant)
            .is_err()
    );
}

/// The TAP is the running guest's NIC: its absence means the guest's link
/// is gone, so adoption fails rather than creating one, and the address it
/// took goes back to the pool.
#[test]
#[cfg(target_os = "linux")]
fn adopt_refuses_a_missing_tap_and_frees_the_address() {
    let pool = || TapNetwork::new("10.0.98.0/24", "10.0.98.1", vec![]).unwrap();
    let allocation = pool().reserve("box").unwrap();
    let manager = pool();
    let error = manager
        .adopt("box", &allocation, AttachMode::Invariant)
        .unwrap_err();
    assert!(error.to_string().contains(&allocation.tap_name), "{error}");
    assert!(
        !manager
            .allocated
            .lock()
            .unwrap()
            .contains(&u32::from(allocation.ip_address)),
        "a refused adoption keeps no address"
    );
}

#[tokio::test]
async fn startup_waiter_unblocks_after_host_finalization() {
    let root = tempfile::tempdir().unwrap();
    let manager = std::sync::Arc::new(
        TapNetwork::with_quarantine_dir(
            "10.0.0.0/30",
            "10.0.0.1",
            vec![],
            root.path().join("network-quarantine"),
            Datapath::default(),
            Arc::new(IptablesLegacy::default()),
        )
        .unwrap(),
    );
    manager.mark_reconciled();

    let waiter = {
        let manager = std::sync::Arc::clone(&manager);
        tokio::spawn(async move {
            manager.wait_startup_cleanup_complete().await;
        })
    };
    tokio::task::yield_now().await;
    assert!(!waiter.is_finished());

    let token = manager.startup_cleanup_token().unwrap();
    manager.finalize_startup_cleanup(&token).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
        .await
        .expect("startup waiter must wake")
        .unwrap();
}

#[test]
#[cfg(not(target_os = "linux"))]
fn durable_quarantine_blocks_reuse_until_startup_and_generation_finalize() {
    let root = tempfile::tempdir().unwrap();
    let quarantine = root.path().join("network-quarantine");
    let manager = TapNetwork::with_quarantine_dir(
        "10.0.0.0/30",
        "10.0.0.1",
        vec![],
        quarantine.clone(),
        Datapath::default(),
        Arc::new(IptablesLegacy::default()),
    )
    .unwrap();
    manager.mark_reconciled();
    let first_startup = manager.startup_cleanup_token().unwrap();
    manager.finalize_startup_cleanup(&first_startup).unwrap();
    let allocation = manager.reserve("old").unwrap();
    quarantine::write_quarantine(&quarantine, "old", &allocation).unwrap();
    drop(manager);

    let restarted = TapNetwork::with_quarantine_dir(
        "10.0.0.0/30",
        "10.0.0.1",
        vec![],
        quarantine,
        Datapath::default(),
        Arc::new(IptablesLegacy::default()),
    )
    .unwrap();
    restarted.mark_reconciled();
    assert!(restarted.reserve("new").is_err());
    assert!(restarted.validate_startup_cleanup(&first_startup).is_err());
    assert!(
        restarted
            .validate_quarantine("old", "wrong-generation")
            .is_err()
    );

    let startup = restarted.startup_cleanup_token().unwrap();
    assert!(restarted.finalize_startup_cleanup(&startup).is_err());
    assert!(
        restarted.reserve("new").is_err(),
        "the quarantined generation must keep the startup gate closed"
    );
    restarted
        .finalize_quarantine("old", &allocation.cleanup_token)
        .unwrap();
    assert!(restarted.reserve("new").is_err());
    restarted.finalize_startup_cleanup(&startup).unwrap();
    let reused = restarted.reserve("new").unwrap();
    assert_eq!(reused.ip_address, allocation.ip_address);
}

/// A `VmId` may start with a dot, so its marker is a dotfile; the loader
/// must still read it — it skips staging leftovers by their `.tmp` shape,
/// not by the leading dot — or the address silently returns to the pool
/// on restart while the marker lingers unlisted.
#[test]
#[cfg(not(target_os = "linux"))]
fn quarantine_of_a_dotted_id_survives_reload() {
    let root = tempfile::tempdir().unwrap();
    let quarantine = root.path().join("network-quarantine");
    let network = || {
        TapNetwork::with_quarantine_dir(
            "10.0.0.0/30",
            "10.0.0.1",
            vec![],
            quarantine.clone(),
            Datapath::default(),
            Arc::new(IptablesLegacy::default()),
        )
        .unwrap()
    };
    let first = network();
    first.mark_reconciled();
    let startup = first.startup_cleanup_token().unwrap();
    first.finalize_startup_cleanup(&startup).unwrap();
    let allocation = first.reserve(".hidden").unwrap();
    first.quarantine_checked(".hidden", &allocation).unwrap();
    // A staging leftover of the shape a crash mid-write leaves behind.
    std::fs::write(quarantine.join(".hidden-stale.tmp"), b"{").unwrap();
    drop(first);

    let restarted = network();
    assert_eq!(
        restarted.pending_quarantines(),
        vec![(".hidden".to_owned(), allocation.cleanup_token)]
    );
    assert!(
        restarted
            .allocated
            .lock()
            .unwrap()
            .contains(&u32::from(allocation.ip_address)),
        "the quarantined address stays out of the pool"
    );
}

#[test]
fn quarantine_loader_rejects_foreign_or_inconsistent_allocations() {
    let mutations: [fn(&mut NetworkAllocation); 4] = [
        |allocation: &mut NetworkAllocation| {
            allocation.ip_address = "192.0.2.2".parse().unwrap();
        },
        |allocation: &mut NetworkAllocation| {
            allocation.tap_name = "vmtap-wrong".into();
        },
        |allocation: &mut NetworkAllocation| {
            allocation.mac_address = "02:00:00:00:00:00".into();
        },
        |allocation: &mut NetworkAllocation| {
            allocation.gateway = "10.0.0.9".parse().unwrap();
        },
    ];
    for mutate in mutations {
        let root = tempfile::tempdir().unwrap();
        let quarantine = root.path().join("network-quarantine");
        std::fs::create_dir(&quarantine).unwrap();
        let mut allocation = NetworkAllocation {
            tap_name: tap_name_from_ip("10.0.0.2".parse().unwrap()),
            ip_address: "10.0.0.2".parse().unwrap(),
            prefix_len: 30,
            gateway: "10.0.0.1".parse().unwrap(),
            mac_address: mac_from_vm_id("box").to_string(),
            dns_servers: vec![],
            cleanup_token: Uuid::new_v4().to_string(),
        };
        mutate(&mut allocation);
        quarantine::write_quarantine(&quarantine, "box", &allocation).unwrap();
        assert!(
            TapNetwork::with_quarantine_dir(
                "10.0.0.0/30",
                "10.0.0.1",
                vec![],
                quarantine,
                Datapath::default(),
                Arc::new(IptablesLegacy::default()),
            )
            .is_err()
        );
    }
}
