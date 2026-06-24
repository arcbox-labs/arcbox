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
