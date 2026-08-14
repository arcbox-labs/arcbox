use super::boot::{agent_timeout_error, ensure_earlycon, with_container_network};
use super::types::{DesiredBoot, machine_drift_reason, metadata_image_filename};
use super::*;
use crate::machine::MachineState;
use crate::vm::ensure_sparse_block_image;
use arcbox_constants::cmdline::HV_EARLYCON_DIRECTIVE;
use arcbox_constants::container_network::ContainerNetwork;

#[test]
fn test_lifecycle_state_is_ready() {
    assert!(!VmLifecycleState::NotExist.is_ready());
    assert!(!VmLifecycleState::Creating.is_ready());
    assert!(!VmLifecycleState::Created.is_ready());
    assert!(!VmLifecycleState::Starting.is_ready());
    assert!(VmLifecycleState::Running.is_ready());
    assert!(VmLifecycleState::Idle.is_ready());
    assert!(!VmLifecycleState::Stopping.is_ready());
    assert!(!VmLifecycleState::Stopped.is_ready());
    assert!(!VmLifecycleState::Failed.is_ready());
}

#[test]
fn test_lifecycle_state_needs_start() {
    assert!(VmLifecycleState::NotExist.needs_start());
    assert!(!VmLifecycleState::Creating.needs_start());
    assert!(VmLifecycleState::Created.needs_start());
    assert!(!VmLifecycleState::Starting.needs_start());
    assert!(!VmLifecycleState::Running.needs_start());
    assert!(!VmLifecycleState::Idle.needs_start());
    assert!(!VmLifecycleState::Stopping.needs_start());
    assert!(VmLifecycleState::Stopped.needs_start());
    assert!(VmLifecycleState::Failed.needs_start());
}

#[test]
fn ensure_earlycon_upgrades_bare_on_hv() {
    let out = ensure_earlycon(
        "console=hvc0 earlycon root=/dev/vda".to_string(),
        arcbox_vmm::VmBackend::Hv,
    );
    assert!(out.contains(HV_EARLYCON_DIRECTIVE));
    // The bare token is replaced, not left dangling alongside the directive.
    assert!(!out.split_whitespace().any(|t| t == "earlycon"));
}

#[test]
fn ensure_earlycon_leaves_vz_untouched() {
    // VZ has no PL011 device; the cmdline must pass through verbatim.
    let cmdline = "console=hvc0 earlycon root=/dev/vda".to_string();
    let out = ensure_earlycon(cmdline.clone(), arcbox_vmm::VmBackend::Vz);
    assert_eq!(out, cmdline);
    assert!(!out.contains("pl011"));
}

#[test]
fn ensure_earlycon_respects_explicit_directive() {
    let cmdline = "console=hvc0 earlycon=pl011,0x9000000 root=/dev/vda".to_string();
    let out = ensure_earlycon(cmdline.clone(), arcbox_vmm::VmBackend::Hv);
    assert_eq!(out, cmdline);
}

#[test]
fn container_network_cmdline_is_authoritative_and_unique() {
    let network: ContainerNetwork = "10.64.0.0/16".parse().unwrap();
    let cmdline = with_container_network(
        "root=/dev/vda arcbox.container_network=172.16.0.0/12 console=hvc0".to_string(),
        network,
    );

    assert!(cmdline.contains("arcbox.container_network=10.64.0.0/16"));
    assert!(!cmdline.contains("172.16.0.0/12"));
    assert_eq!(
        cmdline
            .split_whitespace()
            .filter(|token| token.starts_with("arcbox.container_network="))
            .count(),
        1
    );
}

#[test]
fn agent_timeout_error_folds_last_error() {
    let bare = agent_timeout_error(None).to_string();
    assert!(bare.contains("timeout waiting for agent"));
    assert!(!bare.contains("last error"));

    let folded = agent_timeout_error(Some("guest reported: disk full")).to_string();
    assert!(folded.contains("timeout waiting for agent"));
    assert!(folded.contains("guest reported: disk full"));
}

#[test]
fn test_default_config() {
    let config = VmLifecycleConfig::default();
    assert!(config.auto_stop);
    assert_eq!(config.max_retries, DEFAULT_MAX_RETRIES);
}

#[test]
fn ensure_sparse_block_image_is_thin_provisioned() {
    // Regression guard (issue #244 / ABXD-95): a freshly created data image
    // must be thin — report its full virtual size yet consume virtually no
    // physical disk. A reintroduced upfront preallocation (e.g. macOS
    // `F_PREALLOCATE`) would balloon the allocated block count and fail here.
    let dir = tempfile::tempdir().unwrap();
    // Nested path also exercises parent-directory creation.
    let path = dir.path().join("data").join("docker.img");
    let size_bytes = DOCKER_DATA_IMAGE_SIZE_BYTES; // 8 TiB virtual size

    ensure_sparse_block_image(&path, size_bytes).unwrap();

    let meta = std::fs::metadata(&path).unwrap();
    assert_eq!(
        meta.len(),
        size_bytes,
        "logical size must match the requested virtual size"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // `blocks()` counts 512-byte blocks actually allocated on disk. A
        // sparse file reserves none up front; 1 MiB of slack covers any
        // filesystem metadata overhead while still catching a multi-GiB
        // preallocation regression.
        let physical_bytes = meta.blocks() * 512;
        assert!(
            physical_bytes < 1024 * 1024,
            "image must be sparse: {physical_bytes} physical bytes allocated \
             for an empty {size_bytes}-byte image"
        );
    }
}

#[test]
fn ensure_sparse_block_image_never_shrinks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("docker.img");

    ensure_sparse_block_image(&path, 8192).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 8192);

    // A call with a smaller virtual size must not truncate the existing
    // image — that would discard guest data.
    ensure_sparse_block_image(&path, 4096).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 8192);

    // A larger size grows it.
    ensure_sparse_block_image(&path, 16384).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 16384);
}

#[test]
fn test_default_vm_config() {
    let config = DefaultVmConfig::default();
    assert_eq!(config.cpus, arcbox_hypervisor::default_vm_cpu_count());
    // Default memory is half of host RAM, clamped to [512, 16384] MB.
    let expected_mb = arcbox_hypervisor::default_vm_memory_size() / (1024 * 1024);
    assert_eq!(config.memory_mb, expected_mb);
    assert!(config.memory_mb >= 512);
    assert!(config.memory_mb <= 16384);
    assert_eq!(config.disk_gb, 50);
}

fn sample_machine(cpus: u32, memory_mb: u64, kernel: &str, cmdline: &str) -> MachineInfo {
    MachineInfo {
        name: "default".to_string(),
        state: MachineState::Created,
        vm_id: crate::vm::VmId::new(),
        cid: None,
        cpus,
        memory_mb,
        disk_gb: 50,
        kernel: Some(kernel.to_string()),
        cmdline: Some(cmdline.to_string()),
        block_devices: vec![
            crate::vm::BlockDeviceConfig {
                path: "/rootfs.erofs".to_string(),
                read_only: true,
            },
            crate::vm::BlockDeviceConfig {
                path: "/data/docker.img".to_string(),
                read_only: false,
            },
            crate::vm::BlockDeviceConfig {
                path: "/data/docker-meta.img".to_string(),
                read_only: false,
            },
        ],
        distro: None,
        distro_version: None,
        disk_path: None,
        ssh_key_path: None,
        ip_address: None,
        backend: arcbox_vmm::VmBackend::default(),
        created_at: chrono::Utc::now(),
        started_at: None,
        mounts: Vec::new(),
    }
}

#[test]
fn machine_drift_detects_each_overridable_field() {
    let want = DefaultVmConfig {
        cpus: 4,
        memory_mb: 4096,
        ..DefaultVmConfig::default()
    };
    let boot = DesiredBoot {
        kernel: "/k".to_string(),
        cmdline: "console=hvc0 earlycon".to_string(),
        rootfs_image: std::path::PathBuf::from("/rootfs.erofs"),
    };
    let current = sample_machine(want.cpus, want.memory_mb, &boot.kernel, &boot.cmdline);

    // Matching machine: no drift.
    assert_eq!(machine_drift_reason(&current, &want, Some(&boot)), None);

    // Each overridable field, changed independently, is detected.
    let mut m = current.clone();
    m.cpus = want.cpus + 1;
    assert_eq!(machine_drift_reason(&m, &want, Some(&boot)), Some("cpus"));

    let mut m = current.clone();
    m.memory_mb = want.memory_mb + 1;
    assert_eq!(
        machine_drift_reason(&m, &want, Some(&boot)),
        Some("memory_mb")
    );

    let mut m = current.clone();
    m.kernel = Some("/other-kernel".to_string());
    assert_eq!(machine_drift_reason(&m, &want, Some(&boot)), Some("kernel"));

    // The cmdline gap that previously slipped through (e.g. arm64.nosve
    // added/removed without bumping the boot-asset version).
    let mut m = current.clone();
    m.cmdline = Some("console=hvc0 earlycon arm64.nosve".to_string());
    assert_eq!(
        machine_drift_reason(&m, &want, Some(&boot)),
        Some("cmdline")
    );

    // A machine persisted before the ext4 metadata volume (two disks) must
    // be recreated so the guest receives vdc.
    let mut m = current.clone();
    m.block_devices.pop();
    assert_eq!(
        machine_drift_reason(&m, &want, Some(&boot)),
        Some("block_devices")
    );

    // A machine persisted while a fourth runtime disk was attached must be
    // recreated now that the runtime lives on the existing Btrfs data disk.
    let mut m = current;
    m.block_devices.push(crate::vm::BlockDeviceConfig {
        path: "/boot/runtime.erofs".to_string(),
        read_only: true,
    });
    assert_eq!(
        machine_drift_reason(&m, &want, Some(&boot)),
        Some("block_devices")
    );
    assert_eq!(machine_drift_reason(&m, &want, None), Some("block_devices"));
}

#[test]
fn metadata_image_filename_pairs_with_data_image() {
    assert_eq!(metadata_image_filename("docker.img"), "docker-meta.img");
    assert_eq!(
        metadata_image_filename("docker-rosetta.img"),
        "docker-rosetta-meta.img"
    );
}
