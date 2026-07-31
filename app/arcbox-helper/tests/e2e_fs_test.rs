//! End-to-end filesystem tests against the **real** `arcbox-helper` binary.
//!
//! Spawns `CARGO_BIN_EXE_arcbox-helper` with:
//! - `ARCBOX_HELPER_SOCKET` → temp socket
//! - `ARCBOX_HELPER_TEST_ROOT` → sandbox that relocates `/usr/local/bin`,
//!   `/var/run/docker.sock`, `/etc/resolver`, `/etc/hosts` (debug builds only)
//!
//! No root required. Release builds ignore `TEST_ROOT`; these tests therefore
//! only pass against a debug binary (which `cargo test` builds).
//!
//! Covers the regressions that bit users:
//! - docker CLI symlink install / foreign-link preservation / unlink ownership
//! - docker.sock symlink install / foreign preservation
//! - DNS resolver marker ownership
//! - hosts alias install / uninstall
//! - version pin shape

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use arcbox_helper::HOSTS_ALIAS_LINE;
use arcbox_helper::client::Client;

struct HelperFixture {
    _sandbox: tempfile::TempDir,
    /// Home-shaped tree under `$HOME` so CliTarget / is_arcbox_owned accept paths.
    home_root: PathBuf,
    sandbox_root: PathBuf,
    sock: PathBuf,
    child: Child,
}

impl HelperFixture {
    async fn start() -> Self {
        let sandbox = tempfile::tempdir().expect("sandbox tempdir");
        let sandbox_root = sandbox.path().to_path_buf();

        // Seed empty hosts so read does not fail before install.
        let etc = sandbox_root.join("etc");
        fs::create_dir_all(&etc).unwrap();
        fs::write(etc.join("hosts"), "##\n127.0.0.1\tlocalhost\n").unwrap();

        let home = std::env::var("HOME").expect("HOME required for CliTarget-shaped paths");
        // Unique per fixture so parallel tokio tests do not collide. All tests
        // share one process, so the PID is not distinguishing; a monotonic
        // counter guarantees a distinct root even when two fixtures start
        // within the same nanosecond.
        static FIXTURE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let home_root = PathBuf::from(&home).join(format!(
            ".arcbox-helper-e2e-{}-{}",
            std::process::id(),
            FIXTURE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&home_root);
        fs::create_dir_all(&home_root).unwrap();

        let sock = sandbox_root.join("helper.sock");
        let bin = env!("CARGO_BIN_EXE_arcbox-helper");

        let child = Command::new(bin)
            .env("ARCBOX_HELPER_SOCKET", &sock)
            .env("ARCBOX_HELPER_TEST_ROOT", &sandbox_root)
            // Keep logs out of the way; helper still creates log dir under sandbox.
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn arcbox-helper");

        // Wait until the socket accepts connections.
        let client = wait_for_client(&sock).await;
        // Smoke: version RPC works against the real binary.
        let version = client.version().await.expect("version");
        assert_eq!(
            version,
            format!("arcbox-helper {}", env!("CARGO_PKG_VERSION")),
            "real binary version line"
        );

        Self {
            _sandbox: sandbox,
            home_root,
            sandbox_root,
            sock,
            child,
        }
    }

    fn client(&self) -> impl std::future::Future<Output = Client> + '_ {
        async move {
            Client::connect_to(self.sock.to_str().unwrap())
                .await
                .expect("connect")
        }
    }

    fn bin_dir(&self) -> PathBuf {
        self.sandbox_root.join("usr/local/bin")
    }

    fn docker_sock(&self) -> PathBuf {
        self.sandbox_root.join("var/run/docker.sock")
    }

    fn resolver_dir(&self) -> PathBuf {
        self.sandbox_root.join("etc/resolver")
    }

    fn hosts_path(&self) -> PathBuf {
        self.sandbox_root.join("etc/hosts")
    }

    /// Creates `$HOME/.../Apps/ArcBox.app/Contents/MacOS/xbin/{name}` regular file.
    fn install_xbin_tool(&self, name: &str) -> PathBuf {
        let xbin = self.home_root.join("Apps/ArcBox.app/Contents/MacOS/xbin");
        fs::create_dir_all(&xbin).unwrap();
        let path = xbin.join(name);
        fs::write(&path, b"#!/bin/sh\necho mock\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&path, perms).unwrap();
        }
        path
    }
}

impl Drop for HelperFixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.home_root);
    }
}

async fn wait_for_client(sock: &Path) -> Client {
    let sock_str = sock.to_str().unwrap();
    for _ in 0..100 {
        if let Ok(c) = Client::connect_to(sock_str).await {
            return c;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "helper did not open socket at {} within 2s — is this a debug build?",
        sock.display()
    );
}

// ── version ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn e2e_version_matches_crate() {
    let fx = HelperFixture::start().await;
    let client = fx.client().await;
    let v = client.version().await.unwrap();
    assert_eq!(
        arcbox_constants::helper::parse_helper_version(&v),
        arcbox_constants::helper::parse_semver_triple(env!("CARGO_PKG_VERSION"))
    );
    assert!(arcbox_constants::helper::helper_version_satisfies(
        arcbox_constants::helper::parse_helper_version(&v).unwrap(),
        arcbox_constants::helper::parse_semver_triple(arcbox_constants::helper::MIN_HELPER_VERSION)
            .unwrap()
    ));
}

// ── CLI docker symlink (the user-visible regression) ─────────────────────

#[tokio::test]
async fn e2e_cli_link_installs_docker_under_usr_local_bin() {
    let fx = HelperFixture::start().await;
    let target = fx.install_xbin_tool("docker");
    let target_s = target.to_str().unwrap();

    let client = fx.client().await;
    client.cli_link("docker", target_s).await.unwrap();

    let link = fx.bin_dir().join("docker");
    assert!(
        link.symlink_metadata().unwrap().file_type().is_symlink(),
        "docker must be a symlink at {}",
        link.display()
    );
    assert_eq!(fs::read_link(&link).unwrap(), target);

    // Idempotent.
    client.cli_link("docker", target_s).await.unwrap();
    assert_eq!(fs::read_link(&link).unwrap(), target);

    // Unlink removes ours.
    client.cli_unlink("docker").await.unwrap();
    assert!(
        !link.exists(),
        "ArcBox-owned docker symlink must be removed"
    );
}

#[tokio::test]
async fn e2e_cli_link_refuses_symlink_target() {
    let fx = HelperFixture::start().await;
    let xbin = fx.home_root.join("Apps/ArcBox.app/Contents/MacOS/xbin");
    fs::create_dir_all(&xbin).unwrap();
    let real = fx.home_root.join("evil-bin");
    fs::write(&real, b"#!/bin/sh\n").unwrap();
    let link_target = xbin.join("docker");
    symlink(&real, &link_target).unwrap();

    let client = fx.client().await;
    let err = client
        .cli_link("docker", link_target.to_str().unwrap())
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("symlink"),
        "must refuse symlink CLI target, got: {msg}"
    );
    assert!(!fx.bin_dir().join("docker").exists());
}

#[tokio::test]
async fn e2e_cli_link_preserves_foreign_symlink() {
    let fx = HelperFixture::start().await;
    let target = fx.install_xbin_tool("docker");

    fs::create_dir_all(fx.bin_dir()).unwrap();
    let foreign = fx.bin_dir().join("docker");
    symlink("/usr/local/bin/real-docker", &foreign).unwrap();

    let client = fx.client().await;
    let err = client
        .cli_link("docker", target.to_str().unwrap())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not ArcBox-owned"), "got: {err}");
    assert_eq!(
        fs::read_link(&foreign).unwrap(),
        PathBuf::from("/usr/local/bin/real-docker")
    );

    // Unlink must also leave foreign alone.
    client.cli_unlink("docker").await.unwrap();
    assert!(foreign.symlink_metadata().unwrap().file_type().is_symlink());
}

#[tokio::test]
async fn e2e_cli_link_replaces_stale_arcbox_symlink() {
    let fx = HelperFixture::start().await;
    let target = fx.install_xbin_tool("docker");

    fs::create_dir_all(fx.bin_dir()).unwrap();
    let link = fx.bin_dir().join("docker");
    symlink(
        "/Applications/OldArcBox.app/Contents/MacOS/xbin/docker",
        &link,
    )
    .unwrap();

    let client = fx.client().await;
    client
        .cli_link("docker", target.to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(fs::read_link(&link).unwrap(), target);
}

#[tokio::test]
async fn e2e_cli_link_rejects_bad_name_and_path() {
    let fx = HelperFixture::start().await;
    let client = fx.client().await;

    let err = client
        .cli_link("rm", "/Applications/ArcBox.app/Contents/MacOS/xbin/rm")
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("docker")
            || err.to_string().contains("not allowed")
            || err.to_string().contains("invalid"),
        "got: {err}"
    );

    let err = client.cli_link("docker", "/tmp/evil").await.unwrap_err();
    assert!(
        err.to_string().contains("/Users/")
            || err.to_string().contains("/Applications/")
            || err.to_string().contains("xbin"),
        "got: {err}"
    );
}

// ── docker.sock ──────────────────────────────────────────────────────────

#[tokio::test]
async fn e2e_socket_link_and_unlink() {
    let fx = HelperFixture::start().await;
    // SocketTarget requires /Users/…/.arcbox/…
    let home = std::env::var("HOME").unwrap();
    let sock_target = format!("{home}/.arcbox/run/docker.sock");

    let client = fx.client().await;
    client.socket_link(&sock_target).await.unwrap();

    let link = fx.docker_sock();
    assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(fs::read_link(&link).unwrap(), PathBuf::from(&sock_target));

    // Idempotent.
    client.socket_link(&sock_target).await.unwrap();

    client.socket_unlink().await.unwrap();
    assert!(!link.exists());
}

#[tokio::test]
async fn e2e_socket_preserves_foreign_and_real_file() {
    let fx = HelperFixture::start().await;
    let home = std::env::var("HOME").unwrap();
    let sock_target = format!("{home}/.arcbox/run/docker.sock");

    let link = fx.docker_sock();
    fs::create_dir_all(link.parent().unwrap()).unwrap();

    // Foreign symlink.
    symlink("/var/run/other.sock", &link).unwrap();
    let client = fx.client().await;
    let err = client.socket_link(&sock_target).await.unwrap_err();
    assert!(err.to_string().contains("not ArcBox-owned"), "got: {err}");
    assert_eq!(
        fs::read_link(&link).unwrap(),
        PathBuf::from("/var/run/other.sock")
    );
    client.socket_unlink().await.unwrap();
    assert!(link.symlink_metadata().unwrap().file_type().is_symlink());

    // Real file (Docker Desktop stand-in).
    fs::remove_file(&link).unwrap();
    fs::write(&link, b"not-a-symlink").unwrap();
    let err = client.socket_link(&sock_target).await.unwrap_err();
    assert!(err.to_string().contains("not a symlink"), "got: {err}");
    client.socket_unlink().await.unwrap();
    assert!(link.is_file(), "real socket file must survive unlink");
}

// ── DNS resolver ─────────────────────────────────────────────────────────

#[tokio::test]
async fn e2e_dns_install_status_uninstall() {
    let fx = HelperFixture::start().await;
    let client = fx.client().await;

    assert!(!client.dns_status("arcbox.local").await.unwrap());
    client.dns_install("arcbox.local", 5553).await.unwrap();
    assert!(client.dns_status("arcbox.local").await.unwrap());

    let path = fx.resolver_dir().join("arcbox.local");
    let content = fs::read_to_string(&path).unwrap();
    assert!(content.contains("# managed by arcbox-helper"));
    assert!(content.contains("nameserver 127.0.0.1"));
    assert!(content.contains("port 5553"));

    // Idempotent overwrite of ours.
    client.dns_install("arcbox.local", 5553).await.unwrap();

    client.dns_uninstall("arcbox.local").await.unwrap();
    assert!(!path.exists());
    assert!(!client.dns_status("arcbox.local").await.unwrap());
}

#[tokio::test]
async fn e2e_dns_preserves_foreign_resolver() {
    let fx = HelperFixture::start().await;
    fs::create_dir_all(fx.resolver_dir()).unwrap();
    let path = fx.resolver_dir().join("arcbox.local");
    fs::write(&path, "nameserver 1.1.1.1\n").unwrap();

    let client = fx.client().await;
    let err = client.dns_install("arcbox.local", 5553).await.unwrap_err();
    assert!(err.to_string().contains("not ArcBox-managed"), "got: {err}");
    assert_eq!(fs::read_to_string(&path).unwrap(), "nameserver 1.1.1.1\n");
    assert!(!client.dns_status("arcbox.local").await.unwrap());

    client.dns_uninstall("arcbox.local").await.unwrap();
    assert!(path.exists(), "foreign resolver must survive uninstall");
}

// ── hosts alias ──────────────────────────────────────────────────────────

#[tokio::test]
async fn e2e_hosts_alias_install_uninstall() {
    let fx = HelperFixture::start().await;
    let client = fx.client().await;

    assert!(!client.hosts_alias_status().await.unwrap());
    client.hosts_alias_install().await.unwrap();
    assert!(client.hosts_alias_status().await.unwrap());

    let content = fs::read_to_string(fx.hosts_path()).unwrap();
    assert!(content.contains(HOSTS_ALIAS_LINE));
    assert!(
        content.contains("localhost"),
        "must keep existing hosts lines"
    );

    // Idempotent.
    client.hosts_alias_install().await.unwrap();
    let once = fs::read_to_string(fx.hosts_path()).unwrap();
    assert_eq!(
        once.matches(HOSTS_ALIAS_LINE).count(),
        1,
        "must not duplicate alias line"
    );

    client.hosts_alias_uninstall().await.unwrap();
    assert!(!client.hosts_alias_status().await.unwrap());
    let after = fs::read_to_string(fx.hosts_path()).unwrap();
    assert!(!after.contains(HOSTS_ALIAS_LINE));
    assert!(after.contains("localhost"));
}

// ── validation still enforced on real server ─────────────────────────────

#[tokio::test]
async fn e2e_validation_rejects_bad_inputs() {
    let fx = HelperFixture::start().await;
    let client = fx.client().await;

    assert!(client.socket_link("/tmp/docker.sock").await.is_err());
    assert!(client.dns_install("UPPER.CASE", 5553).await.is_err());
    assert!(client.dns_install("arcbox.local", 53).await.is_err());
    assert!(client.route_add("8.8.8.0/24", "bridge100").await.is_err());
}
