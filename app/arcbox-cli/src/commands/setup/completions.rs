use std::path::Path;

use anyhow::{Context, Result};
use clap::CommandFactory;

use super::super::Cli;
use super::ShellKind;

pub(super) fn print(shell: ShellKind) {
    let mut command = Cli::command();
    clap_complete::generate(
        clap_shell(shell),
        &mut command,
        "abctl",
        &mut std::io::stdout(),
    );
}

pub(super) fn generate_all(directory: &Path) -> Result<()> {
    let shells = [
        (clap_complete::Shell::Zsh, directory.join("zsh/_abctl")),
        (clap_complete::Shell::Bash, directory.join("bash/abctl")),
        (
            clap_complete::Shell::Fish,
            directory.join("fish/abctl.fish"),
        ),
    ];

    for (shell, path) in shells {
        let mut command = Cli::command();
        let mut output = Vec::new();
        clap_complete::generate(shell, &mut command, "abctl", &mut output);
        std::fs::write(&path, output)
            .with_context(|| format!("failed to write completions to {}", path.display()))?;
    }

    Ok(())
}

const fn clap_shell(shell: ShellKind) -> clap_complete::Shell {
    match shell {
        ShellKind::Zsh => clap_complete::Shell::Zsh,
        ShellKind::Bash => clap_complete::Shell::Bash,
        ShellKind::Fish => clap_complete::Shell::Fish,
    }
}

#[cfg(test)]
mod tests {
    use super::generate_all;

    #[test]
    fn generates_each_supported_completion_file() {
        let directory = tempfile::tempdir().unwrap();
        for shell in ["zsh", "bash", "fish"] {
            std::fs::create_dir(directory.path().join(shell)).unwrap();
        }

        generate_all(directory.path()).unwrap();

        assert!(directory.path().join("zsh/_abctl").is_file());
        assert!(directory.path().join("bash/abctl").is_file());
        assert!(directory.path().join("fish/abctl.fish").is_file());
    }
}
