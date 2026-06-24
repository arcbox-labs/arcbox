use std::{env, path::PathBuf, process::Command};

use anyhow::{Context, Result, bail};
#[cfg(target_os = "macos")]
use xtask_kit::apple;
use xtask_kit::{process, repo};

use crate::{MacosArgs, MacosCommand};

pub fn run(args: MacosArgs) -> Result<()> {
    match args.command {
        MacosCommand::Dev(args) => run_dev(args),
    }
}

fn run_dev(args: crate::MacosDevArgs) -> Result<()> {
    let shell = process::shell()?;
    let root = repo::root_from_xtask_manifest(env!("CARGO_MANIFEST_DIR"))?;
    shell.change_dir(&root);
    let release = args.profile == "release";
    if args.profile != "debug" && !release {
        bail!("--profile must be debug or release");
    }

    if release {
        xshell::cmd!(
            shell,
            "cargo build -p arcbox-cli -p arcbox-daemon --release"
        )
        .run()?;
    } else {
        xshell::cmd!(shell, "cargo build -p arcbox-cli -p arcbox-daemon").run()?;
    }

    let default_kernel = root.join("boot-assets/dev/kernel");
    let kernel = args.kernel.unwrap_or_else(|| default_kernel.clone());
    if kernel == default_kernel {
        crate::commands::dev::prepare_boot_assets(crate::BootAssetsArgs {
            source: None,
            version: None,
            data_dir: None,
            kernel_dir: None,
        })?;
    }
    if !kernel.is_file() {
        bail!("kernel not found: {}", kernel.display());
    }

    let bin = if release {
        root.join("target/release/arcbox-daemon")
    } else {
        root.join("target/debug/arcbox-daemon")
    };

    if args.sign {
        let entitlements = args
            .entitlements
            .unwrap_or_else(|| root.join("bundle/arcbox.dev.entitlements"));
        sign_daemon(&bin, &entitlements)?;
    }

    let helper_socket = args
        .helper_socket
        .or_else(|| env::var_os("ARCBOX_HELPER_SOCKET").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/tmp/arcbox-helper.sock"));

    let status = Command::new(&bin)
        .env("ARCBOX_HELPER_SOCKET", helper_socket)
        .arg("--socket")
        .arg(args.socket)
        .arg("--grpc-socket")
        .arg(args.grpc_socket)
        .arg("--data-dir")
        .arg(args.data_dir)
        .arg("--kernel")
        .arg(kernel)
        .arg("--guest-docker-vsock-port")
        .arg(args.guest_docker_vsock_port.to_string())
        .status()
        .with_context(|| format!("running {}", bin.display()))?;

    if !status.success() {
        bail!("arcbox-daemon exited with {status}");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn sign_daemon(bin: &std::path::Path, entitlements: &std::path::Path) -> Result<()> {
    let mut codesign = apple::CodesignOptions::runtime("-", bin);
    codesign.entitlements = Some(entitlements);
    apple::codesign(&codesign)?;
    let entitlements_xml = apple::entitlements_xml(bin)?;
    if !entitlements_xml.contains("com.apple.security.virtualization") {
        bail!(
            "missing com.apple.security.virtualization entitlement on {}",
            bin.display()
        );
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn sign_daemon(_bin: &std::path::Path, _entitlements: &std::path::Path) -> Result<()> {
    bail!("macOS signing is only available on macOS")
}
