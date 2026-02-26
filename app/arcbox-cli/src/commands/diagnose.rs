//! Diagnostic command implementation.
//!
//! Outputs runtime readiness, boot assets validation, and key socket status.

use anyhow::Result;
use arcbox_core::{
    BootAssetProvider, Config, DefaultVmConfig, Runtime, boot_assets::BOOT_ASSET_VERSION,
    machine::MachineInfo,
};
use std::path::Path;

#[derive(Default)]
struct RuntimeReadiness {
    daemon_running: bool,
    runtime_default_vm: Option<DefaultVmConfig>,
    default_machine: Option<MachineInfo>,
}

/// Executes the diagnose command.
pub async fn execute() -> Result<()> {
    let config = Config::load().unwrap_or_default();

    println!("=== ArcBox Diagnostics ===");
    println!();

    // 1. System info
    print_system_info();

    // 2. Socket status
    println!("--- Sockets ---");
    check_socket("Docker socket", &config.docker.socket_path);
    println!();

    // 3. Boot assets validation
    println!("--- Boot Assets ---");
    check_boot_assets(&config).await;
    println!();

    // 4. Runtime readiness
    println!("--- Runtime ---");
    let runtime_readiness = check_runtime_readiness(&config).await;
    println!();

    // 5. Data directories
    println!("--- Data Directories ---");
    check_directory("data_dir", &config.data_dir);
    check_directory("images", &config.images_dir());
    check_directory("containers", &config.containers_dir());
    check_directory("machines", &config.machines_dir());
    check_directory("volumes", &config.volumes_dir());
    println!();

    // 6. Configuration summary
    print_configuration_summary(&config, &runtime_readiness);

    Ok(())
}

fn print_system_info() {
    println!("--- System ---");
    println!("  Version:  {}", env!("CARGO_PKG_VERSION"));
    println!("  OS:       {}", std::env::consts::OS);
    println!("  Arch:     {}", std::env::consts::ARCH);
    println!(
        "  CPUs:     {}",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    );
    println!();
}

fn check_socket(label: &str, path: &Path) {
    if path.exists() {
        println!("  {} ({}): OK", label, path.display());
    } else {
        println!("  {} ({}): NOT FOUND", label, path.display());
    }
}

fn check_directory(label: &str, path: &Path) {
    if path.is_dir() {
        println!("  {}: {} (exists)", label, path.display());
    } else {
        println!("  {}: {} (missing)", label, path.display());
    }
}

async fn check_boot_assets(config: &Config) {
    let boot_dir = config.data_dir.join("boot");
    println!("  Expected version: {}", BOOT_ASSET_VERSION);
    println!("  Cache dir:        {}", boot_dir.display());

    let provider = BootAssetProvider::new(boot_dir);
    let cached = provider.is_cached();
    println!("  Cached:           {}", if cached { "yes" } else { "no" });

    if cached {
        match provider.read_cached_manifest().await {
            Ok(Some(manifest)) => {
                println!("  Manifest version: {}", manifest.asset_version);
                println!("  Manifest arch:    {}", manifest.arch);
                if let Some(ref commit) = manifest.kernel_commit {
                    println!("  Kernel commit:    {}", commit);
                }
                if let Some(ref commit) = manifest.agent_commit {
                    println!("  Agent commit:     {}", commit);
                }
                if let Some(ref built_at) = manifest.built_at {
                    println!("  Built at:         {}", built_at);
                }
                if !manifest.runtime_assets.is_empty() {
                    println!("  Runtime assets:");
                    for asset in &manifest.runtime_assets {
                        let ver = asset.version.as_deref().unwrap_or("unknown");
                        println!("    - {} v{}", asset.name, ver);
                    }
                }
            }
            Ok(None) => {
                println!(
                    "  Manifest:         missing (kernel/initramfs present but no manifest.json)"
                );
            }
            Err(e) => {
                println!("  Manifest:         ERROR - {}", e);
            }
        }
    }

    // Check custom kernel/initramfs paths.
    if let Some(ref kernel) = config.vm.kernel_path {
        let status = if kernel.exists() { "OK" } else { "NOT FOUND" };
        println!("  Custom kernel:    {} ({})", kernel.display(), status);
    }
    if let Some(ref initrd) = config.vm.initrd_path {
        let status = if initrd.exists() { "OK" } else { "NOT FOUND" };
        println!("  Custom initramfs: {} ({})", initrd.display(), status);
    }
}

fn print_configuration_summary(config: &Config, runtime: &RuntimeReadiness) {
    println!("--- Configuration ---");
    println!("  Container provision: {:?}", config.container.provision);
    println!("  Provision mode:    {:?}", config.container.provision);

    if let Some(info) = runtime.default_machine.as_ref() {
        println!("  VM CPUs:           {} (running machine)", info.cpus);
        println!(
            "  VM Memory:         {} MB (running machine)",
            info.memory_mb
        );
        if let Some(kernel) = info.kernel.as_deref() {
            println!("  VM Kernel:         {} (running machine)", kernel);
        }
        if let Some(initrd) = info.initrd.as_deref() {
            println!("  VM Initramfs:      {} (running machine)", initrd);
        }
    } else if let Some(default_vm) = runtime.runtime_default_vm.as_ref() {
        println!("  VM CPUs:           {} (runtime default)", default_vm.cpus);
        println!(
            "  VM Memory:         {} MB (runtime default)",
            default_vm.memory_mb
        );
        if let Some(kernel) = default_vm.kernel.as_ref() {
            println!(
                "  VM Kernel:         {} (runtime default)",
                kernel.display()
            );
        }
        if let Some(initramfs) = default_vm.initramfs.as_ref() {
            println!(
                "  VM Initramfs:      {} (runtime default)",
                initramfs.display()
            );
        }
        if runtime.daemon_running {
            println!("  VM Config Source:  local runtime defaults");
        }
    } else {
        println!("  VM CPUs:           {} (config)", config.vm.cpus);
        println!("  VM Memory:         {} MB (config)", config.vm.memory_mb);
        if let Some(kernel) = config.vm.kernel_path.as_ref() {
            println!("  VM Kernel:         {} (config)", kernel.display());
        }
        if let Some(initramfs) = config.vm.initrd_path.as_ref() {
            println!("  VM Initramfs:      {} (config)", initramfs.display());
        }
        if runtime.daemon_running {
            println!("  VM Config Source:  local config (runtime unavailable)");
        }
    }

    println!("  Network subnet:    {}", config.network.subnet);
}

async fn check_runtime_readiness(config: &Config) -> RuntimeReadiness {
    // Check daemon connectivity.
    let daemon = arcbox_cli::client::DaemonClient::new();
    let daemon_running = daemon.is_running().await;
    println!(
        "  Daemon:           {}",
        if daemon_running {
            "running"
        } else {
            "not running"
        }
    );
    println!("  Daemon socket:    {}", daemon.socket_path().display());

    if !daemon_running {
        println!("  VM state:         unknown (daemon not running)");
        println!("  Health:           unknown (daemon not running)");
        return RuntimeReadiness::default();
    }

    // Try to instantiate Runtime to check VM lifecycle state.
    match Runtime::new(config.clone()) {
        Ok(runtime) => {
            let vm_lifecycle = runtime.vm_lifecycle();
            let runtime_default_vm = Some(vm_lifecycle.default_vm_config());

            let state = vm_lifecycle.state().await;
            println!("  VM state:         {}", state.as_str());

            let healthy = vm_lifecycle.health_monitor().is_healthy();
            println!(
                "  Health:           {}",
                if healthy { "healthy" } else { "UNHEALTHY" }
            );

            let default_machine = vm_lifecycle.default_machine_info();
            if let Some(info) = default_machine.as_ref() {
                println!("  Machine name:     {}", info.name);
                println!("  Machine CPUs:     {}", info.cpus);
                println!("  Machine memory:   {} MB", info.memory_mb);
                if let Some(cid) = info.cid {
                    println!("  Machine CID:      {}", cid);
                }
                if let Some(kernel) = info.kernel.as_deref() {
                    println!("  Machine kernel:   {}", kernel);
                }
                if let Some(initrd) = info.initrd.as_deref() {
                    println!("  Machine initrd:   {}", initrd);
                }
            } else {
                println!("  Default machine:  not created");
            }

            // Container/image counts via daemon API.
            let containers: Vec<arcbox_cli::client::ContainerSummary> = daemon
                .get("/v1.43/containers/json?all=true")
                .await
                .unwrap_or_default();
            let running = containers.iter().filter(|c| c.state == "running").count();
            println!(
                "  Containers:       {} total, {} running",
                containers.len(),
                running
            );

            let images: Vec<arcbox_cli::client::ImageSummary> =
                daemon.get("/v1.43/images/json").await.unwrap_or_default();
            println!("  Images:           {}", images.len());

            RuntimeReadiness {
                daemon_running: true,
                runtime_default_vm,
                default_machine,
            }
        }
        Err(e) => {
            println!("  Runtime init:     ERROR - {}", e);
            RuntimeReadiness {
                daemon_running: true,
                runtime_default_vm: None,
                default_machine: None,
            }
        }
    }
}
