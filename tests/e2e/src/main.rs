use std::path::PathBuf;

use anyhow::Result;
use clap::{ArgAction, Args, Parser, Subcommand};
use tracing::error;
use tracing_subscriber::EnvFilter;

mod boot_assets;

#[derive(Parser)]
#[command(author, version, about = "ArcBox end-to-end test runner")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the boot assets VM and Docker lifecycle integration test.
    BootAssets(BootAssetsArgs),
}

#[derive(Args)]
struct BootAssetsArgs {
    /// Skip rebuilding release binaries before the test.
    #[arg(long, action = ArgAction::SetTrue)]
    skip_build: bool,
    /// Preserve the temporary test directory after the test exits.
    #[arg(long, action = ArgAction::SetTrue)]
    keep_test_dir: bool,
    /// Boot asset version to test. Defaults to assets.lock [boot].version.
    #[arg(long, env = "ARCBOX_BOOT_ASSET_VERSION")]
    version: Option<String>,
    /// Guest Docker vsock port to pass to arcbox-daemon.
    #[arg(long, env = "ARCBOX_GUEST_DOCKER_VSOCK_PORT", default_value_t = 2375)]
    guest_docker_vsock_port: u32,
}

fn main() {
    init_tracing();

    if let Err(error) = run() {
        error!(error = %format_args!("{error:#}"), "command failed");
        std::process::exit(1);
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::BootAssets(args) => boot_assets::run(args),
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("tests/e2e lives two levels below the repository root")
        .to_owned()
}
