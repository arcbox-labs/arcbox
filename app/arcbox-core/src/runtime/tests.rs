use super::Runtime;
use super::assets::{check_executable, ensure_guest_binaries};
use super::kubeconfig::rewrite_kubeconfig_server;
use crate::config::Config;
use std::path::PathBuf;

#[test]
fn test_ensure_guest_binaries_ok() {
    let temp_dir = tempfile::tempdir().unwrap();
    let data_dir = temp_dir.path();

    std::fs::create_dir_all(data_dir.join("bin")).unwrap();
    std::fs::create_dir_all(data_dir.join("runtime/bin")).unwrap();

    for name in [
        "bin/arcbox-agent",
        "runtime/bin/dockerd",
        "runtime/bin/containerd",
        "runtime/bin/containerd-shim-runc-v2",
        "runtime/bin/runc",
        "runtime/bin/docker-init",
        "runtime/bin/k3s",
    ] {
        let path = data_dir.join(name);
        std::fs::write(&path, b"binary").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    let result = ensure_guest_binaries(data_dir);
    assert!(result.is_ok(), "expected success, got {result:?}");
}

#[test]
fn test_ensure_guest_binaries_missing_agent() {
    let temp_dir = tempfile::tempdir().unwrap();
    let err = ensure_guest_binaries(temp_dir.path()).unwrap_err();
    assert!(
        err.to_string().contains("agent binary not found"),
        "got: {err}"
    );
}

#[test]
fn test_ensure_guest_binaries_missing_runtime() {
    let temp_dir = tempfile::tempdir().unwrap();
    let data_dir = temp_dir.path();

    let agent = data_dir.join("bin/arcbox-agent");
    std::fs::create_dir_all(agent.parent().unwrap()).unwrap();
    std::fs::write(&agent, b"agent").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let err = ensure_guest_binaries(data_dir).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("runtime binary"), "got: {msg}");
}

#[test]
fn test_rewrite_kubeconfig_server_updates_arcbox_refs() {
    let kubeconfig = "apiVersion: v1\nclusters:\n- cluster:\n    server: https://127.0.0.1:6443\n  name: default\ncontexts:\n- context:\n    cluster: default\n    user: default\n  name: default\ncurrent-context: default\nusers:\n- name: default\n  user: {}\n";

    let rewritten = rewrite_kubeconfig_server(kubeconfig);
    assert!(rewritten.contains("server: https://127.0.0.1:16443"));
    assert!(rewritten.contains("name: arcbox"));
    assert!(rewritten.contains("- name: arcbox"));
    assert!(rewritten.contains("cluster: arcbox"));
    assert!(rewritten.contains("user: arcbox"));
    assert!(rewritten.contains("current-context: arcbox"));
}

#[cfg(unix)]
#[test]
fn test_check_executable_not_executable() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("not-exec");
    std::fs::write(&path, b"data").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let err = check_executable(&path, "test").unwrap_err();
    assert!(err.to_string().contains("not executable"), "got: {err}");
}

fn networking_test_runtime() -> (Runtime, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().unwrap();
    let config = Config {
        data_dir: temp_dir.path().to_path_buf(),
        ..Default::default()
    };
    let runtime = Runtime::new(config).expect("runtime init should succeed");
    (runtime, temp_dir)
}

#[tokio::test]
async fn resolve_registered_container_by_id_alias_and_prefix() {
    let (runtime, _tmp) = networking_test_runtime();
    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    let id = "0a1b2c3d4e5f00112233445566778899";
    runtime.register_dns(id, &["web.local".into()], ip).await;
    runtime.register_container_alias("web", id).await;

    // Exact canonical ID.
    assert_eq!(
        runtime.resolve_registered_container(id).await.as_deref(),
        Some(id)
    );
    // Name alias.
    assert_eq!(
        runtime.resolve_registered_container("web").await.as_deref(),
        Some(id)
    );
    // Unique short-ID prefix.
    assert_eq!(
        runtime
            .resolve_registered_container("0a1b2c3d4e5f")
            .await
            .as_deref(),
        Some(id)
    );
    // Unregistered token resolves to nothing.
    assert_eq!(runtime.resolve_registered_container("nope").await, None);
}

#[tokio::test]
async fn resolve_registered_container_rejects_ambiguous_prefix() {
    let (runtime, _tmp) = networking_test_runtime();
    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    runtime
        .register_dns("abcd1111", &["a.local".into()], ip)
        .await;
    runtime
        .register_dns("abcd2222", &["b.local".into()], ip)
        .await;

    // Prefix matching two registered IDs must not guess.
    assert_eq!(runtime.resolve_registered_container("abcd").await, None);
    // Longer, unique prefixes still resolve.
    assert_eq!(
        runtime
            .resolve_registered_container("abcd1")
            .await
            .as_deref(),
        Some("abcd1111")
    );
}

#[tokio::test]
async fn container_names_invert_aliases_and_prefer_the_shortest() {
    let (runtime, _tmp) = networking_test_runtime();
    let id = "0a1b2c3d4e5f00112233445566778899";
    // A container accreting two names: the short primary and a longer alias.
    runtime.register_container_alias("db", id).await;
    runtime
        .register_container_alias("arcbox-postgres-1", id)
        .await;
    // A second container with a single name.
    runtime.register_container_alias("cache", "beef5678").await;

    let names = runtime.container_names().await;
    assert_eq!(names.get(id).map(String::as_str), Some("db"));
    assert_eq!(names.get("beef5678").map(String::as_str), Some("cache"));
    // Unknown IDs have no name (the consumer falls back to the short ID).
    assert!(!names.contains_key("unknown"));
}

#[tokio::test]
async fn deregister_dns_clears_aliases_even_without_dns_entry() {
    let (runtime, _tmp) = networking_test_runtime();
    // Alias registered without any DNS entry (e.g. port forwarding only).
    runtime
        .register_container_alias("ports-only", "feed1234")
        .await;
    assert_eq!(
        runtime
            .resolve_registered_container("ports-only")
            .await
            .as_deref(),
        Some("feed1234")
    );

    runtime.deregister_dns_by_id("feed1234").await;
    assert_eq!(
        runtime.resolve_registered_container("ports-only").await,
        None
    );
}

#[test]
fn test_runtime_new_propagates_config_vm_defaults() {
    let temp_dir = tempfile::tempdir().unwrap();

    let mut config = Config {
        data_dir: temp_dir.path().to_path_buf(),
        ..Default::default()
    };
    config.vm.cpus = 6;
    config.vm.memory_mb = 3072;
    config.vm.kernel_path = Some(PathBuf::from("/tmp/arcbox-test-kernel"));

    let runtime = Runtime::new(config).expect("runtime init should succeed");
    let default_vm = runtime.vm_lifecycle().default_vm_config();

    assert_eq!(default_vm.cpus, 6);
    assert_eq!(default_vm.memory_mb, 3072);
    assert_eq!(
        default_vm.kernel,
        Some(PathBuf::from("/tmp/arcbox-test-kernel"))
    );
}

#[test]
fn resolve_bind_ip_defaults_and_loopback() {
    use std::net::Ipv4Addr;
    // Sandbox exposures pass "127.0.0.1" and must bind loopback only.
    assert_eq!(
        super::resolve_bind_ip("127.0.0.1"),
        Some(Ipv4Addr::LOCALHOST)
    );
    // Published container ports (empty / explicit 0.0.0.0) bind all interfaces.
    assert_eq!(super::resolve_bind_ip(""), Some(Ipv4Addr::UNSPECIFIED));
    assert_eq!(
        super::resolve_bind_ip("0.0.0.0"),
        Some(Ipv4Addr::UNSPECIFIED)
    );
    // A specific address is honored; garbage is rejected.
    assert_eq!(
        super::resolve_bind_ip("10.0.0.5"),
        Some(Ipv4Addr::new(10, 0, 0, 5))
    );
    assert_eq!(super::resolve_bind_ip("not-an-ip"), None);
}
