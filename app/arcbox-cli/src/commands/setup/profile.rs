use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::process::Command;

use super::{ShellKind, bin_dir, completions_dir, shell_dir};

const PROFILE_MARKER: &str = "# Added by ArcBox: command-line tools and integration";
const BASELINE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
const PROBE_PREFIX: &str = "__ARCBOX_SHELL_PROBE__";

#[derive(Debug)]
pub(super) struct LoginProbe {
    pub path_ok: bool,
    pub completion_ok: bool,
    pub detail: Option<String>,
}

pub(super) fn detect_shell() -> ShellKind {
    std::env::var("SHELL")
        .ok()
        .and_then(|shell| {
            if shell.contains("zsh") {
                Some(ShellKind::Zsh)
            } else if shell.contains("bash") {
                Some(ShellKind::Bash)
            } else if shell.contains("fish") {
                Some(ShellKind::Fish)
            } else {
                None
            }
        })
        .unwrap_or(ShellKind::Zsh)
}

pub(super) fn init_path(shell: ShellKind) -> PathBuf {
    shell_dir().join(format!("init.{}", shell.as_str()))
}

pub(super) fn completion_path(shell: ShellKind) -> PathBuf {
    match shell {
        ShellKind::Zsh => completions_dir().join("zsh/_abctl"),
        ShellKind::Bash => completions_dir().join("bash/abctl"),
        ShellKind::Fish => completions_dir().join("fish/abctl.fish"),
    }
}

pub(super) async fn profile_path(shell: ShellKind) -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(match shell {
        ShellKind::Zsh => effective_zdotdir(&home).await?.join(".zprofile"),
        ShellKind::Bash => home.join(".bash_profile"),
        ShellKind::Fish => home.join(".config/fish/config.fish"),
    })
}

pub(super) async fn inject(shell: ShellKind, path: PathBuf) -> Result<PathBuf> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let existing = read(&path).await?.unwrap_or_default();
    let updated = normalized_profile(&existing, shell, Some(&source_snippet(shell)));
    if updated != existing {
        tokio::fs::write(&path, updated)
            .await
            .with_context(|| format!("failed to update {}", path.display()))?;
    }
    Ok(path)
}

pub(super) async fn remove(shell: ShellKind, path: PathBuf) -> Result<Option<PathBuf>> {
    let Some(existing) = read(&path).await? else {
        return Ok(None);
    };
    let updated = normalized_profile(&existing, shell, None);
    if updated == existing {
        return Ok(None);
    }
    tokio::fs::write(&path, updated)
        .await
        .with_context(|| format!("failed to update {}", path.display()))?;
    Ok(Some(path))
}

pub(super) async fn is_injected(path: &Path, shell: ShellKind) -> Result<bool> {
    Ok(read(path).await?.is_some_and(|content| {
        content.matches(PROFILE_MARKER).count() == 1
            && content.matches(&source_snippet(shell)).count() == 1
    }))
}

pub(super) async fn probe_login(shell: ShellKind) -> LoginProbe {
    match run_login_probe(shell).await {
        Ok((path_ok, completion_ok)) => LoginProbe {
            path_ok,
            completion_ok,
            detail: None,
        },
        Err(error) => LoginProbe {
            path_ok: false,
            completion_ok: false,
            detail: Some(format!("{error:#}")),
        },
    }
}

fn source_snippet(shell: ShellKind) -> String {
    let suffix = if matches!(shell, ShellKind::Fish) {
        "; or true"
    } else {
        " 2>/dev/null || :"
    };
    format!(
        "{PROFILE_MARKER}\nsource \"{}\"{suffix}",
        init_path(shell).display()
    )
}

fn normalized_profile(content: &str, shell: ShellKind, snippet: Option<&str>) -> String {
    let mut lines = content.lines().peekable();
    let mut kept = Vec::new();
    while let Some(line) = lines.next() {
        if line == PROFILE_MARKER {
            if lines
                .peek()
                .is_some_and(|line| is_managed_source(line, shell))
            {
                lines.next();
            }
        } else {
            kept.push(line);
        }
    }
    while kept.last().is_some_and(|line| line.is_empty()) {
        kept.pop();
    }

    let mut result = kept.join("\n");
    if let Some(snippet) = snippet {
        if !result.is_empty() {
            result.push_str("\n\n");
        }
        result.push_str(snippet);
    }
    if !result.is_empty() {
        result.push('\n');
    }
    result
}

fn is_managed_source(line: &str, shell: ShellKind) -> bool {
    let suffix = if matches!(shell, ShellKind::Fish) {
        "\"; or true"
    } else {
        "\" 2>/dev/null || :"
    };
    line.strip_prefix("source \"")
        .and_then(|line| line.strip_suffix(suffix))
        .is_some_and(|path| {
            Path::new(path).ends_with(Path::new("shell").join(format!("init.{}", shell.as_str())))
        })
}

async fn read(path: &Path) -> Result<Option<String>> {
    match tokio::fs::read_to_string(path).await {
        Ok(content) => Ok(Some(content)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

async fn effective_zdotdir(home: &Path) -> Result<PathBuf> {
    let shell = shell_binary(ShellKind::Zsh);
    effective_zdotdir_with(&shell, home, None).await
}

async fn effective_zdotdir_with(
    shell: &Path,
    home: &Path,
    isolated_home: Option<&Path>,
) -> Result<PathBuf> {
    let command = format!("printf '{PROBE_PREFIX}%s\\n' \"${{ZDOTDIR:-$HOME}}\"");
    let output = run_shell(shell, &command, isolated_home).await?;
    let value = probe_value(&output).context("zsh did not report its effective ZDOTDIR")?;
    let path = PathBuf::from(value);
    Ok(if path.is_absolute() {
        path
    } else {
        home.join(path)
    })
}

async fn run_login_probe(shell: ShellKind) -> Result<(bool, bool)> {
    let bin = bin_dir();
    let completion = completion_path(shell);
    run_login_probe_with(shell, &shell_binary(shell), &bin, &completion, None).await
}

async fn run_login_probe_with(
    shell: ShellKind,
    shell_binary: &Path,
    bin: &Path,
    completion: &Path,
    isolated_home: Option<&Path>,
) -> Result<(bool, bool)> {
    let command = match shell {
        ShellKind::Zsh => format!(
            "command -v abctl >/dev/null && [[ $(command -v abctl) == {}/abctl ]]; p=$?; d={}; [[ -r {} && ${{fpath[(Ie)$d]}} -ne 0 ]]; c=$?; printf '{PROBE_PREFIX}%s:%s\\n' $p $c",
            shell_quote(bin),
            shell_quote(completion.parent().expect("completion has parent")),
            shell_quote(completion),
        ),
        ShellKind::Bash => format!(
            "test \"$(command -v abctl)\" = {}/abctl; p=$?; complete -p abctl >/dev/null 2>&1 && test -r {}; c=$?; printf '{PROBE_PREFIX}%s:%s\\n' $p $c",
            shell_quote(bin),
            shell_quote(completion),
        ),
        ShellKind::Fish => format!(
            "test (command -v abctl) = {}/abctl; set p $status; complete -C abctl >/dev/null; and test -r {}; set c $status; printf '{PROBE_PREFIX}%s:%s\\n' $p $c",
            shell_quote(bin),
            shell_quote(completion),
        ),
    };
    let output = run_shell(shell_binary, &command, isolated_home).await?;
    match probe_value(&output).and_then(|value| value.split_once(':')) {
        Some((path, completion)) => Ok((path == "0", completion == "0")),
        None => bail!("{} returned an invalid health probe", shell.as_str()),
    }
}

async fn run_shell(shell: &Path, command: &str, isolated_home: Option<&Path>) -> Result<String> {
    let mut child = Command::new(shell);
    child
        .args(["-l", "-c", command])
        .env("PATH", BASELINE_PATH)
        .kill_on_drop(true);
    if let Some(home) = isolated_home {
        child.env("HOME", home).env_remove("ZDOTDIR");
    }
    let output = tokio::time::timeout(Duration::from_secs(3), child.output())
        .await
        .context("login shell probe timed out")??;
    if !output.status.success() {
        bail!(
            "{} login shell exited with {}: {}",
            shell.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout).context("login shell output was not UTF-8")
}

fn shell_binary(shell: ShellKind) -> PathBuf {
    std::env::var_os("SHELL")
        .filter(|path| {
            Path::new(path)
                .file_name()
                .is_some_and(|name| name == shell.as_str())
        })
        .map_or_else(
            || PathBuf::from(format!("/bin/{}", shell.as_str())),
            PathBuf::from,
        )
}

fn probe_value(output: &str) -> Option<&str> {
    output
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix(PROBE_PREFIX))
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::{PROFILE_MARKER, ShellKind, normalized_profile, probe_value, source_snippet};

    #[test]
    fn profile_normalization_removes_duplicate_injections() {
        let snippet = source_snippet(ShellKind::Zsh);
        let existing = format!("export KEEP=1\n{snippet}\n\n{snippet}\n");

        let installed = normalized_profile(&existing, ShellKind::Zsh, Some(&snippet));
        assert_eq!(installed.matches(PROFILE_MARKER).count(), 1);
        assert!(installed.contains("export KEEP=1"));
        assert_eq!(
            normalized_profile(&installed, ShellKind::Zsh, Some(&snippet)),
            installed
        );
        assert_eq!(
            normalized_profile(&installed, ShellKind::Zsh, None),
            "export KEEP=1\n"
        );
    }

    #[test]
    fn orphaned_marker_preserves_the_following_user_line() {
        let existing = format!("{PROFILE_MARKER}\nexport KEEP=1\n");

        assert_eq!(
            normalized_profile(&existing, ShellKind::Zsh, None),
            "export KEEP=1\n"
        );
    }

    #[test]
    fn stale_managed_source_is_replaced_and_remains_removable() {
        let stale = "source \"/old/arcbox/shell/init.zsh\" 2>/dev/null || :";
        let existing = format!("{PROFILE_MARKER}\n{stale}\nexport KEEP=1\n");
        let current = source_snippet(ShellKind::Zsh);

        let installed = normalized_profile(&existing, ShellKind::Zsh, Some(&current));
        assert!(!installed.contains(stale));
        assert!(installed.contains(&current));
        assert_eq!(
            normalized_profile(&installed, ShellKind::Zsh, None),
            "export KEEP=1\n"
        );
    }

    #[test]
    fn probe_parser_uses_the_last_sentinel() {
        assert_eq!(
            probe_value("profile noise\n__ARCBOX_SHELL_PROBE__old\n__ARCBOX_SHELL_PROBE__ok\n"),
            Some("ok")
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn zsh_probe_honors_effective_zdotdir_and_login_environment() {
        use std::os::unix::fs::PermissionsExt as _;
        use std::path::Path;

        use super::{ShellKind, effective_zdotdir_with, run_login_probe_with};

        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().join("home");
        let zdotdir = home.join("zdotdir");
        let bin = directory.path().join("bin");
        let completions = directory.path().join("completions/zsh");
        let init = directory.path().join("init.zsh");
        for path in [&home, &zdotdir, &bin, &completions] {
            std::fs::create_dir_all(path).unwrap();
        }
        std::fs::write(home.join(".zshenv"), "export ZDOTDIR=$HOME/zdotdir\n").unwrap();
        std::fs::write(
            &init,
            format!(
                "export PATH=\"{}:$PATH\"\nfpath+=(\"{}\")\n",
                bin.display(),
                completions.display()
            ),
        )
        .unwrap();
        std::fs::write(
            zdotdir.join(".zprofile"),
            format!("source \"{}\"\n", init.display()),
        )
        .unwrap();
        let abctl = bin.join("abctl");
        std::fs::write(&abctl, "#!/bin/sh\n").unwrap();
        let mut permissions = std::fs::metadata(&abctl).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&abctl, permissions).unwrap();
        let completion = completions.join("_abctl");
        std::fs::write(&completion, "#compdef abctl\n").unwrap();

        assert_eq!(
            effective_zdotdir_with(Path::new("/bin/zsh"), &home, Some(&home))
                .await
                .unwrap(),
            zdotdir
        );
        assert_eq!(
            run_login_probe_with(
                ShellKind::Zsh,
                Path::new("/bin/zsh"),
                &bin,
                &completion,
                Some(&home),
            )
            .await
            .unwrap(),
            (true, true)
        );
    }
}
