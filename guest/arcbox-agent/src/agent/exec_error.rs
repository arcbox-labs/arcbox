use std::path::Path;

use crate::rpc::ErrorResponse;

pub(super) fn spawn_error(
    command: &str,
    working_dir: &str,
    path: Option<&str>,
    error: std::io::Error,
) -> ErrorResponse {
    if error.kind() == std::io::ErrorKind::NotFound
        && requested_executable_is_missing(command, working_dir, path)
    {
        ErrorResponse::new(404, format!("command not found: '{command}': {error}"))
    } else {
        ErrorResponse::new(500, format!("failed to spawn command '{command}': {error}"))
    }
}

fn requested_executable_is_missing(command: &str, working_dir: &str, path: Option<&str>) -> bool {
    let working_dir = (!working_dir.is_empty()).then(|| Path::new(working_dir));
    if working_dir.is_some_and(|dir| !dir.is_dir()) {
        return false;
    }

    let command_path = Path::new(command);
    if command_path.is_absolute() || command.contains(std::path::MAIN_SEPARATOR) {
        let resolved =
            working_dir.map_or_else(|| command_path.to_path_buf(), |dir| dir.join(command_path));
        return !resolved.is_file();
    }

    let Some(path) = path.map(Into::into).or_else(|| std::env::var_os("PATH")) else {
        return false;
    };
    !std::env::split_paths(&path).any(|dir| {
        let candidate = if dir.is_absolute() {
            dir.join(command)
        } else if let Some(working_dir) = working_dir {
            working_dir.join(dir).join(command)
        } else {
            dir.join(command)
        };
        candidate.is_file()
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[test]
    fn spawn_error_classifies_only_a_missing_executable_as_not_found() {
        let search_dir = tempfile::tempdir().unwrap();
        let path = search_dir.path().to_str().unwrap();
        let missing = spawn_failure("arcbox-command-that-does-not-exist", "", Some(path));
        assert_eq!(missing.code, 404);
        assert!(
            missing
                .message
                .contains("arcbox-command-that-does-not-exist")
        );

        let missing_working_dir = search_dir.path().join("missing-working-directory");
        let cwd_error = spawn_failure(
            "./arcbox-command-that-does-not-exist",
            missing_working_dir.to_str().unwrap(),
            None,
        );
        assert_eq!(cwd_error.code, 500);

        let script = search_dir.path().join("missing-interpreter");
        std::fs::write(&script, "#!/arcbox/no-such-interpreter\n").unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
        let interpreter_error = spawn_failure(script.to_str().unwrap(), "", None);
        assert_eq!(interpreter_error.code, 500);
    }

    fn spawn_failure(command: &str, working_dir: &str, path: Option<&str>) -> ErrorResponse {
        let mut process = std::process::Command::new(command);
        if !working_dir.is_empty() {
            process.current_dir(working_dir);
        }
        if let Some(path) = path {
            process.env("PATH", path);
        }
        let error = process
            .spawn()
            .expect_err("test command must fail to spawn");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        spawn_error(command, working_dir, path, error)
    }
}
