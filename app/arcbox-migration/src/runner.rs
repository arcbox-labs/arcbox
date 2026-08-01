//! Docker CLI transport used by migration planning and execution.

use crate::docker_types::{
    ContainerInspect, DockerInfo, ImageInspect, NetworkInspect, VolumeInspect,
};
use crate::error::{MigrationError, Result};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::{Child, Command};

use crate::helper_image::helper_image_reference;

const HELPER_IMAGE_REFERENCE: &str = helper_image_reference();

/// Docker CLI runner bound to a Unix socket.
#[derive(Clone)]
pub struct DockerCliRunner {
    binary: PathBuf,
    socket_path: PathBuf,
    isolated_config: Arc<TempDir>,
}

impl std::fmt::Debug for DockerCliRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DockerCliRunner")
            .field("binary", &self.binary)
            .field("socket_path", &self.socket_path)
            .finish_non_exhaustive()
    }
}

/// Network creation options supported by the CLI transport.
#[derive(Debug, Clone)]
pub struct CreateNetworkOptions {
    /// Whether the network is internal.
    pub internal: bool,
    /// Whether IPv6 is enabled.
    pub enable_ipv6: bool,
    /// Whether the network is attachable.
    pub attachable: bool,
    /// Network labels.
    pub labels: Vec<(String, String)>,
    /// Driver options.
    pub options: Vec<(String, String)>,
    /// IPAM subnet tuples.
    pub ipam: Vec<(String, String, String)>,
}

impl DockerCliRunner {
    /// Creates a new CLI runner for the provided Docker socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the `docker` binary cannot be located.
    pub fn new(socket_path: impl Into<PathBuf>) -> Result<Self> {
        Ok(Self {
            binary: resolve_docker_binary().ok_or_else(|| {
                MigrationError::Docker("failed to locate `docker` in PATH".into())
            })?,
            socket_path: socket_path.into(),
            isolated_config: Arc::new(tempfile::tempdir()?),
        })
    }

    /// Returns the socket path used by this runner.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Returns the helper image reference used for temporary volume containers.
    #[must_use]
    pub const fn helper_image_reference(&self) -> &'static str {
        HELPER_IMAGE_REFERENCE
    }

    /// Returns Docker daemon info.
    pub async fn info(&self) -> Result<DockerInfo> {
        self.json_object(&["info", "--format", "{{json .}}"]).await
    }

    /// Returns all image inspect payloads.
    pub async fn list_images(&self) -> Result<Vec<ImageInspect>> {
        let ids = self.lines(&["image", "ls", "-aq", "--no-trunc"]).await?;
        self.inspect_many::<ImageInspect>("image", &ids).await
    }

    /// Returns all volume inspect payloads.
    pub async fn list_volumes(&self) -> Result<Vec<VolumeInspect>> {
        let names = self.lines(&["volume", "ls", "-q"]).await?;
        self.inspect_many::<VolumeInspect>("volume", &names).await
    }

    /// Returns all user-defined network inspect payloads.
    pub async fn list_networks(&self) -> Result<Vec<NetworkInspect>> {
        let ids = self
            .lines(&["network", "ls", "--filter", "type=custom", "-q"])
            .await?;
        self.inspect_many::<NetworkInspect>("network", &ids).await
    }

    /// Returns all container inspect payloads, including stopped containers.
    pub async fn list_containers(&self) -> Result<Vec<ContainerInspect>> {
        let ids = self
            .lines(&["container", "ls", "-aq", "--no-trunc"])
            .await?;
        self.inspect_many::<ContainerInspect>("container", &ids)
            .await
    }

    /// Stops a container.
    pub async fn stop_container(&self, id: &str) -> Result<()> {
        self.status(["container", "stop", "--time", "30", id]).await
    }

    /// Starts a container.
    pub async fn start_container(&self, id: &str) -> Result<()> {
        self.status(["container", "start", id]).await
    }

    /// Removes a container forcibly.
    pub async fn remove_container(&self, id: &str) -> Result<()> {
        self.status(["container", "rm", "--force", "--volumes", id])
            .await
    }

    /// Removes a volume.
    pub async fn remove_volume(&self, name: &str) -> Result<()> {
        self.status(["volume", "rm", "--force", name]).await
    }

    /// Removes a network.
    pub async fn remove_network(&self, name: &str) -> Result<()> {
        self.status(["network", "rm", name]).await
    }

    /// Creates a volume with labels and options.
    pub async fn create_volume(
        &self,
        name: &str,
        labels: &[(String, String)],
        options: &[(String, String)],
    ) -> Result<()> {
        let mut args = vec!["volume".to_string(), "create".to_string(), name.to_string()];
        for (key, value) in labels {
            args.push("--label".to_string());
            args.push(format!("{key}={value}"));
        }
        for (key, value) in options {
            args.push("--opt".to_string());
            args.push(format!("{key}={value}"));
        }
        self.status_owned(args).await
    }

    /// Creates a network using supported bridge-network flags.
    pub async fn create_network(&self, name: &str, config: &CreateNetworkOptions) -> Result<()> {
        let mut args = vec![
            "network".to_string(),
            "create".to_string(),
            "--driver".to_string(),
            "bridge".to_string(),
        ];
        if config.internal {
            args.push("--internal".to_string());
        }
        if config.enable_ipv6 {
            args.push("--ipv6".to_string());
        }
        if config.attachable {
            args.push("--attachable".to_string());
        }
        for (key, value) in &config.labels {
            args.push("--label".to_string());
            args.push(format!("{key}={value}"));
        }
        for (key, value) in &config.options {
            args.push("--opt".to_string());
            args.push(format!("{key}={value}"));
        }
        for (subnet, gateway, ip_range) in &config.ipam {
            if !subnet.is_empty() {
                args.push("--subnet".to_string());
                args.push(subnet.clone());
            }
            if !gateway.is_empty() {
                args.push("--gateway".to_string());
                args.push(gateway.clone());
            }
            if !ip_range.is_empty() {
                args.push("--ip-range".to_string());
                args.push(ip_range.clone());
            }
        }
        args.push(name.to_string());
        self.status_owned(args).await
    }

    /// Creates a container and returns its ID.
    pub async fn create_container<I, S>(&self, args: I) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let output = self.output(["container", "create"], args).await?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Connects a container to an additional network.
    pub async fn connect_network(
        &self,
        network: &str,
        container: &str,
        aliases: &[String],
    ) -> Result<()> {
        let mut args = vec!["network".to_string(), "connect".to_string()];
        for alias in aliases {
            args.push("--alias".to_string());
            args.push(alias.clone());
        }
        args.push(network.to_string());
        args.push(container.to_string());
        self.status_owned(args).await
    }

    /// Creates a helper container mounting the provided volume at `/volume`.
    pub async fn create_helper_container(&self, name: &str, volume_name: &str) -> Result<String> {
        self.create_container([
            "--name",
            name,
            "--mount",
            &format!("type=volume,src={volume_name},dst=/volume"),
            HELPER_IMAGE_REFERENCE,
            "/helper",
        ])
        .await
    }

    /// Ensures the helper image exists by importing an empty tar archive when needed.
    pub async fn ensure_helper_image(&self) -> Result<()> {
        let status = Command::new(&self.binary)
            .arg("--host")
            .arg(self.host_arg())
            .args(["image", "inspect", HELPER_IMAGE_REFERENCE])
            .env("DOCKER_CONFIG", self.isolated_config.path())
            .env("DOCKER_CLI_HINTS", "false")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await?;
        if status.success() {
            return Ok(());
        }

        let mut child = self
            .command()
            .args(["image", "import", "-", HELPER_IMAGE_REFERENCE])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&empty_tar_bytes()).await?;
        }
        wait_for_success(child, "docker image import").await
    }

    /// Streams `docker save` on this daemon straight into `docker load` on
    /// `target`, returning the number of bytes transferred.
    ///
    /// `references` must list every tag to preserve: `docker save` keeps all
    /// tags of an image only for arguments given without a tag, so naming a
    /// single `repo:tag` silently drops that image's other tags.
    pub async fn pipe_save_into(&self, target: &Self, references: &[String]) -> Result<u64> {
        if references.is_empty() {
            return Err(MigrationError::InvalidPlan(
                "image plan has no export references".into(),
            ));
        }

        let mut save = self
            .command()
            .args(["image", "save"])
            .args(references)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut load = target
            .command()
            .args(["image", "load", "--quiet"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;

        let mut save_stdout = save
            .stdout
            .take()
            .ok_or_else(|| MigrationError::Docker("docker save stdout missing".into()))?;
        let mut load_stdin = load
            .stdin
            .take()
            .ok_or_else(|| MigrationError::Docker("docker load stdin missing".into()))?;

        let copy_task = tokio::spawn(async move {
            let copied = tokio::io::copy(&mut save_stdout, &mut load_stdin).await?;
            load_stdin.shutdown().await?;
            Ok::<u64, std::io::Error>(copied)
        });
        // Drain both stderrs concurrently to prevent pipe buffer deadlocks.
        let save_stderr = tokio::spawn(take_stderr(save.stderr.take()));
        let load_stderr = tokio::spawn(take_stderr(load.stderr.take()));

        let save_status = save.wait().await?;
        let load_status = load.wait().await?;
        let copied = copy_task
            .await
            .map_err(|e| MigrationError::Docker(format!("docker save copy task failed: {e}")))?;
        let save_stderr = save_stderr.await.map_err(|e| {
            MigrationError::Docker(format!("docker save stderr task failed: {e}"))
        })??;
        let load_stderr = load_stderr.await.map_err(|e| {
            MigrationError::Docker(format!("docker load stderr task failed: {e}"))
        })??;

        // Report the producing side first: a `docker load` failure is usually a
        // downstream symptom of `docker save` dying mid-stream.
        if !save_status.success() {
            return Err(MigrationError::Docker(format!(
                "docker image save failed: {}",
                save_stderr.trim()
            )));
        }
        if !load_status.success() {
            return Err(MigrationError::Docker(format!(
                "docker image load failed: {}",
                load_stderr.trim()
            )));
        }
        Ok(copied?)
    }

    /// Streams a container path into a tempfile via `docker cp`.
    ///
    /// `--archive` is required on both halves of a volume transfer: without it
    /// `docker cp` takes ownership from the destination, so every file would
    /// arrive owned by root and databases would refuse to start.
    pub async fn copy_from_container(
        &self,
        container: &str,
        source_path: &str,
    ) -> Result<tempfile::NamedTempFile> {
        let file = tempfile::NamedTempFile::new()?;
        let path = file.path().to_path_buf();
        let mut child = self
            .command()
            .args([
                "container",
                "cp",
                "--archive",
                &format!("{container}:{source_path}"),
                "-",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| MigrationError::Docker("docker cp stdout missing".into()))?;
        let mut dest = tokio::fs::File::create(&path).await?;
        let stdout_task =
            tokio::spawn(async move { tokio::io::copy(&mut stdout, &mut dest).await.map(|_| ()) });
        // Drain stderr concurrently to prevent pipe buffer deadlocks.
        let stderr_task = tokio::spawn(take_stderr(child.stderr.take()));
        let status = child.wait().await?;
        stdout_task
            .await
            .map_err(|e| MigrationError::Docker(format!("docker cp copy task failed: {e}")))??;
        let stderr = stderr_task
            .await
            .map_err(|e| MigrationError::Docker(format!("docker cp stderr task failed: {e}")))??;
        if !status.success() {
            return Err(MigrationError::Docker(format!(
                "docker container cp failed: {}",
                stderr.trim()
            )));
        }
        Ok(file)
    }

    /// Streams a tar archive tempfile into a container via `docker cp`.
    ///
    /// See [`Self::copy_from_container`] for why `--archive` is mandatory.
    pub async fn copy_to_container(
        &self,
        source_archive: &Path,
        container: &str,
        target_path: &str,
    ) -> Result<()> {
        let mut child = self
            .command()
            .args([
                "container",
                "cp",
                "--archive",
                "-",
                &format!("{container}:{target_path}"),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| MigrationError::Docker("docker cp stdin missing".into()))?;
        let mut source = tokio::fs::File::open(source_archive).await?;
        let write_task = tokio::spawn(async move {
            tokio::io::copy(&mut source, &mut stdin).await?;
            stdin.shutdown().await
        });
        // Drain stderr concurrently to prevent pipe buffer deadlocks.
        let stderr_task = tokio::spawn(take_stderr(child.stderr.take()));
        let status = child.wait().await?;
        write_task
            .await
            .map_err(|e| MigrationError::Docker(format!("docker cp write task failed: {e}")))??;
        let stderr = stderr_task
            .await
            .map_err(|e| MigrationError::Docker(format!("docker cp stderr task failed: {e}")))??;
        if !status.success() {
            return Err(MigrationError::Docker(format!(
                "docker container cp failed: {}",
                stderr.trim()
            )));
        }
        Ok(())
    }

    async fn inspect_many<T>(&self, noun: &str, ids: &[String]) -> Result<Vec<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut args = vec![noun.to_string(), "inspect".to_string()];
        args.extend(ids.iter().cloned());
        self.json_array_owned(args).await
    }

    async fn json_object<T>(&self, args: &[&str]) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let output = self
            .output_owned(args.iter().map(ToString::to_string).collect())
            .await?;
        serde_json::from_slice(&output.stdout).map_err(Into::into)
    }

    async fn json_array_owned<T>(&self, args: Vec<String>) -> Result<Vec<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let output = self.output_owned(args).await?;
        serde_json::from_slice(&output.stdout).map_err(Into::into)
    }

    async fn lines(&self, args: &[&str]) -> Result<Vec<String>> {
        let output = self
            .output_owned(args.iter().map(ToString::to_string).collect())
            .await?;
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect())
    }

    async fn status<I, S>(&self, args: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.output_owned(
            args.into_iter()
                .map(|arg| arg.as_ref().to_string())
                .collect(),
        )
        .await
        .map(|_| ())
    }

    async fn status_owned(&self, args: Vec<String>) -> Result<()> {
        self.output_owned(args).await.map(|_| ())
    }

    async fn output<I, S, J, T>(&self, prefix: I, rest: J) -> Result<std::process::Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        J: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let mut args: Vec<String> = prefix
            .into_iter()
            .map(|item| item.as_ref().to_string())
            .collect();
        args.extend(rest.into_iter().map(|item| item.as_ref().to_string()));
        self.output_owned(args).await
    }

    async fn output_owned(&self, args: Vec<String>) -> Result<std::process::Output> {
        let output = self
            .command()
            .args(args)
            .output()
            .await
            .map_err(|e| MigrationError::Docker(format!("failed to run docker: {e}")))?;
        if output.status.success() {
            return Ok(output);
        }
        Err(MigrationError::Docker(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.binary);
        command
            .arg("--host")
            .arg(self.host_arg())
            .env("DOCKER_CONFIG", self.isolated_config.path())
            .env("DOCKER_CLI_HINTS", "false")
            .env("NO_COLOR", "1")
            .kill_on_drop(true);
        command
    }

    fn host_arg(&self) -> String {
        format!("unix://{}", self.socket_path.display())
    }
}

async fn wait_for_success(mut child: Child, context: &str) -> Result<()> {
    let stderr = take_stderr(child.stderr.take()).await?;
    let status = child.wait().await?;
    if status.success() {
        Ok(())
    } else {
        Err(MigrationError::Docker(format!(
            "{context} failed: {}",
            stderr.trim()
        )))
    }
}

async fn take_stderr(stderr: Option<tokio::process::ChildStderr>) -> Result<String> {
    let mut stderr =
        stderr.ok_or_else(|| MigrationError::Docker("docker stderr pipe missing".into()))?;
    let mut buf = Vec::new();
    stderr.read_to_end(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn resolve_docker_binary() -> Option<PathBuf> {
    if let Some(path) = find_in_path("docker") {
        return Some(path);
    }

    let home = dirs::home_dir()?;
    let candidates = [
        home.join(".arcbox/bin/docker"),
        home.join(".arcbox/runtime/bin/docker"),
        PathBuf::from("/opt/homebrew/bin/docker"),
        PathBuf::from("/usr/local/bin/docker"),
        PathBuf::from("/Applications/Docker.app/Contents/Resources/bin/docker"),
    ];
    candidates.into_iter().find(|path: &PathBuf| path.is_file())
}

fn find_in_path(binary: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path_var) {
        let candidate = directory.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn empty_tar_bytes() -> Vec<u8> {
    vec![0; 1024]
}

#[cfg(test)]
mod tests {
    use super::{empty_tar_bytes, find_in_path};

    #[test]
    fn empty_tar_has_two_zero_blocks() {
        assert_eq!(empty_tar_bytes().len(), 1024);
        assert!(empty_tar_bytes().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn path_lookup_handles_missing_binary() {
        assert!(find_in_path("definitely-not-a-real-binary").is_none());
    }
}
