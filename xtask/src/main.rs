use std::path::PathBuf;

use anyhow::Result;
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

mod commands;

#[derive(Parser)]
#[command(author, version, about = "ArcBox repository automation")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Development-only repository orchestration.
    Dev(DevArgs),
    /// Repeated e2e test runs with artifact capture.
    E2e(E2eArgs),
    /// Sample a process's idle CPU% and RSS against the idle targets.
    Idle(IdleArgs),
    /// macOS host build, signing, and local runtime tasks.
    Macos(MacosArgs),
    /// Release metadata and artifact generation.
    Release(ReleaseArgs),
}

#[derive(Args)]
struct E2eArgs {
    /// System VM backend(s) for the daemon under test.
    #[arg(long, value_enum, default_value = "vz")]
    backend: E2eBackend,
    /// Repetitions per backend.
    #[arg(long, default_value_t = 1)]
    repeat: u32,
    /// arcbox-e2e integration test target to run.
    #[arg(long, default_value = "boot_assets")]
    test: String,
    /// Stop at the first failing run.
    #[arg(long)]
    fail_fast: bool,
    /// Artifacts directory (default: target/e2e-artifacts/<unix-time>).
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,
}

#[derive(Args)]
struct IdleArgs {
    /// Process ID to sample (e.g. a running arcbox-daemon).
    #[arg(long)]
    pid: u32,
    /// Sampling window in seconds.
    #[arg(long, default_value_t = 30)]
    seconds: u64,
}

#[derive(Clone, Copy, ValueEnum)]
enum E2eBackend {
    Vz,
    Hv,
    Both,
}

#[derive(Args)]
struct DevArgs {
    #[command(subcommand)]
    command: DevCommand,
}

#[derive(Subcommand)]
enum DevCommand {
    /// Prepare boot assets under boot-assets/dev for local tests and daemons.
    BootAssets(BootAssetsArgs),
    /// Rebuild the committed sandbox NAT BPF object and its source-hash
    /// sidecar (virt/arcbox-vm/bpf). Requires a clang with the BPF backend.
    Bpf,
}

#[derive(Args)]
struct BootAssetsArgs {
    /// Source for development boot assets.
    #[arg(long, value_enum, env = "ARCBOX_DEV_BOOT_SOURCE")]
    source: Option<BootAssetSource>,
    /// Version to prepare. Defaults to assets.lock [boot].version.
    #[arg(long, env = "ARCBOX_BOOT_ASSET_VERSION")]
    version: Option<String>,
    /// User data directory containing downloaded boot assets.
    #[arg(long, env = "ARCBOX_DATA_DIR")]
    data_dir: Option<PathBuf>,
    /// arcbox-kernel checkout used when --source kernel-output is selected.
    #[arg(long, env = "ARCBOX_KERNEL_DIR")]
    kernel_dir: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum BootAssetSource {
    Release,
    KernelOutput,
}

#[derive(Args)]
struct MacosArgs {
    #[command(subcommand)]
    command: MacosCommand,
}

#[derive(Subcommand)]
enum MacosCommand {
    /// Build, locally sign, and run arcbox-daemon for development.
    Dev(MacosDevArgs),
}

#[derive(Args)]
struct MacosDevArgs {
    /// Cargo profile to build: debug or release.
    #[arg(long, env = "PROFILE", default_value = "debug")]
    profile: String,
    /// Kernel image to pass to arcbox-daemon.
    #[arg(long, env = "KERNEL")]
    kernel: Option<PathBuf>,
    /// Docker API socket path.
    #[arg(long, env = "SOCKET", default_value = "/tmp/arcbox.sock")]
    socket: PathBuf,
    /// gRPC socket path.
    #[arg(long, env = "GRPC_SOCKET", default_value = "/tmp/arcbox-grpc.sock")]
    grpc_socket: PathBuf,
    /// Daemon data directory.
    #[arg(long, env = "DATA_DIR", default_value = "/tmp/arcbox-data")]
    data_dir: PathBuf,
    /// Guest Docker vsock port.
    #[arg(long, env = "GUEST_DOCKER_VSOCK_PORT", default_value_t = 2375)]
    guest_docker_vsock_port: u32,
    /// Privileged helper socket path.
    #[arg(long, env = "HELPER_SOCKET")]
    helper_socket: Option<PathBuf>,
    /// Entitlements file for local signing.
    #[arg(long, env = "ENTITLEMENTS")]
    entitlements: Option<PathBuf>,
    /// Sign the local daemon binary before running it.
    #[arg(long, env = "SIGN", default_value_t = true, action = ArgAction::Set)]
    sign: bool,
}

#[derive(Args)]
struct ReleaseArgs {
    #[command(subcommand)]
    command: ReleaseCommand,
}

#[derive(Subcommand)]
enum ReleaseCommand {
    /// Check Docker/Kubernetes tool updates and rewrite assets.lock.
    CheckToolUpdates(CheckToolUpdatesArgs),
    /// Package the desktop release artifacts into a tar.gz and matching .sha256 file.
    PackageTarball(PackageTarballArgs),
    /// Stage a single arcbox-fleet-agent binary as a raw release asset with a .sha256 file.
    FleetAsset(FleetAssetArgs),
}

#[derive(Args)]
struct CheckToolUpdatesArgs {
    /// Path to the asset lockfile to update.
    #[arg(long, default_value = "assets.lock")]
    lockfile: PathBuf,
}

#[derive(Args)]
struct PackageTarballArgs {
    /// Release tag or version, e.g. v0.4.10.
    #[arg(long)]
    version: String,
    /// Directory produced by the host-binaries-darwin-arm64 artifact download.
    #[arg(long, default_value = "artifacts/host")]
    host_artifacts: PathBuf,
    /// Directory produced by the agent-binary-linux-arm64 artifact download.
    #[arg(long, default_value = "artifacts/agent")]
    agent_artifacts: PathBuf,
    /// Directory to write the tarball and checksum into.
    #[arg(long, default_value = ".")]
    output_dir: PathBuf,
}

#[derive(Args)]
struct FleetAssetArgs {
    /// Platform slug used in the asset name (`<os>-<arch>` in the fleet
    /// capability vocabulary), e.g. darwin-arm64, linux-amd64. The version
    /// lives in the release tag, not the asset name.
    #[arg(long)]
    platform: String,
    /// Path to the built arcbox-fleet-agent binary.
    #[arg(long)]
    binary: PathBuf,
    /// Directory to write the asset and checksum into.
    #[arg(long, default_value = ".")]
    output_dir: PathBuf,
}

fn main() {
    if let Err(error) = run() {
        if let Some(exit) = error.downcast_ref::<xtask_kit::process::ExitCode>() {
            std::process::exit(exit.code());
        }
        eprintln!("Error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Dev(args) => commands::dev::run(args),
        Command::E2e(args) => commands::e2e::run(args),
        Command::Idle(args) => commands::idle::run(args),
        Command::Macos(args) => commands::macos::run(args),
        Command::Release(args) => commands::release::run(args),
    }
}
