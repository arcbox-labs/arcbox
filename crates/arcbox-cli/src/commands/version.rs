//! Version command implementation.

use anyhow::Result;

/// Executes the version command.
pub async fn execute() -> Result<()> {
    println!("ArcBox version {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Platform: {} / {}", std::env::consts::OS, std::env::consts::ARCH);
    println!("Rust: {}", rustc_version());

    Ok(())
}

fn rustc_version() -> &'static str {
    // This is set by the build
    option_env!("RUSTC_VERSION").unwrap_or("unknown")
}
