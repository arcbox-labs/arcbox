//! Placeholder binary that redirects users to `abctl`.
//!
//! If arguments are provided, attempts to exec `abctl` transparently so that
//! existing scripts and muscle-memory keep working.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() {
        eprintln!("The ArcBox CLI has been renamed to `abctl`. Please use `abctl` instead.");
        std::process::exit(0);
    }

    // Try to exec `abctl` from the same directory as this binary.
    let exe = std::env::current_exe().ok();
    let abctl_path = exe
        .as_ref()
        .and_then(|p| p.parent())
        .map(|dir| dir.join("abctl"));

    if let Some(ref path) = abctl_path {
        if path.exists() {
            exec_abctl(path, &args);
        }
    }

    // Fallback: try `abctl` from PATH.
    exec_abctl(std::path::Path::new("abctl"), &args);
}

#[cfg(unix)]
fn exec_abctl(path: &std::path::Path, args: &[String]) -> ! {
    use std::os::unix::process::CommandExt;
    // exec replaces the current process; on success this never returns.
    let err = std::process::Command::new(path).args(args).exec();
    eprintln!("Failed to exec abctl: {err}");
    eprintln!(
        "The ArcBox CLI has been renamed to `abctl`. Please install it or add it to your PATH."
    );
    std::process::exit(1);
}

#[cfg(not(unix))]
fn exec_abctl(path: &std::path::Path, args: &[String]) -> ! {
    match std::process::Command::new(path).args(args).status() {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(err) => {
            eprintln!("Failed to run abctl: {err}");
            eprintln!(
                "The ArcBox CLI has been renamed to `abctl`. Please install it or add it to your PATH."
            );
            std::process::exit(1);
        }
    }
}
