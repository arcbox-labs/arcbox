use std::{env, path::PathBuf, process::Command};

use anyhow::{Context, Result, bail};

use crate::{MacosArgs, MacosCommand, support::repo_root};

pub fn run(args: MacosArgs) -> Result<()> {
    match args.command {
        MacosCommand::Dev(args) => run_dev(args),
    }
}

fn run_dev(args: crate::MacosDevArgs) -> Result<()> {
    let shell = xshell::Shell::new()?;
    let root = repo_root();
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
        xshell::cmd!(
            shell,
            "codesign --force --options runtime --entitlements {entitlements} -s - {bin}"
        )
        .run()?;
        let output = Command::new("codesign")
            .args(["-d", "--entitlements", ":-"])
            .arg(&bin)
            .output()
            .with_context(|| format!("reading entitlements from {}", bin.display()))?;
        let entitlements_xml = String::from_utf8_lossy(&output.stderr);
        if !entitlements_xml.contains("com.apple.security.virtualization") {
            bail!(
                "missing com.apple.security.virtualization entitlement on {}",
                bin.display()
            );
        }
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
