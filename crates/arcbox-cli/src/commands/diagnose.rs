//! Diagnostic command implementation.
//!
//! Outputs runtime readiness, boot assets validation, and key socket status.

use anyhow::Result;
use arcbox_core::{BootAssetProvider, Config, Runtime, boot_assets::BOOT_ASSET_VERSION};
use std::path::Path;

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
    check_runtime_readiness(&config).await;
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
    println!("--- Configuration ---");
    println!("  Container backend: {:?}", config.container.backend);
    println!("  Provision mode:    {:?}", config.container.provision);
    println!("  VM CPUs:           {}", config.vm.cpus);
    println!("  VM Memory:         {} MB", config.vm.memory_mb);
    println!("  Network subnet:    {}", config.network.subnet);

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

async fn check_runtime_readiness(config: &Config) {
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
        return;
    }

    // Try to instantiate Runtime to check VM lifecycle state.
    match Runtime::new(config.clone()) {
        Ok(runtime) => {
            let vm_lifecycle = runtime.vm_lifecycle();

            let state = vm_lifecycle.state().await;
            println!("  VM state:         {}", state.as_str());

            let healthy = vm_lifecycle.health_monitor().is_healthy();
            println!(
                "  Health:           {}",
                if healthy { "healthy" } else { "UNHEALTHY" }
            );

            if let Some(info) = vm_lifecycle.default_machine_info() {
                println!("  Machine name:     {}", info.name);
                println!("  Machine CPUs:     {}", info.cpus);
                println!("  Machine memory:   {} MB", info.memory_mb);
                if let Some(cid) = info.cid {
                    println!("  Machine CID:      {}", cid);
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
        }
        Err(e) => {
            println!("  Runtime init:     ERROR - {}", e);
        }
    }
}
