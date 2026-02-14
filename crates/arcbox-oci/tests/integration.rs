//! Integration tests for arcbox-oci crate.
//!
//! These tests verify the interaction between different modules.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use arcbox_oci::{
    Bundle, BundleBuilder, ContainerState, Hook, HookContext, Hooks, Mount, OciError, Spec,
    StateStore, Status,
};

/// Test complete container lifecycle through OCI structures.
#[test]
fn test_container_lifecycle_simulation() {
    let dir = tempfile::tempdir().unwrap();
    let bundle_path = dir.path().join("container-bundle");
    let state_dir = dir.path().join("state");

    // Step 1: Create bundle.
    let bundle = BundleBuilder::new()
        .hostname("lifecycle-test")
        .args(vec![
            "sh".to_string(),
            "-c".to_string(),
            "echo hello".to_string(),
        ])
        .add_env("TEST_VAR", "test_value")
        .cwd("/")
        .user(0, 0)
        .annotation("test.lifecycle", "true")
        .build(&bundle_path)
        .unwrap();

    assert!(bundle.config_path().exists());

    // Step 2: Initialize state store.
    let store = StateStore::new(&state_dir).unwrap();

    // Step 3: Create container state (simulating 'create' command).
    let mut state = ContainerState::new(
        "lifecycle-container".to_string(),
        bundle.path().to_path_buf(),
        bundle.rootfs_path(),
    );
    state.name = Some("my-container".to_string());

    // Save initial state.
    store.save(&state).unwrap();
    assert!(store.exists("lifecycle-container"));
    assert_eq!(state.status(), Status::Creating);

    // Step 4: Mark as created.
    state.mark_created().unwrap();
    store.save(&state).unwrap();

    let loaded = store.load("lifecycle-container").unwrap();
    assert_eq!(loaded.status(), Status::Created);

    // Step 5: Start container (simulating 'start' command).
    state.mark_started(12345).unwrap();
    store.save(&state).unwrap();

    let loaded = store.load("lifecycle-container").unwrap();
    assert_eq!(loaded.status(), Status::Running);
    assert_eq!(loaded.oci_state().pid, Some(12345));

    // Step 6: Stop container.
    state.mark_stopped(0).unwrap();
    store.save(&state).unwrap();

    let loaded = store.load("lifecycle-container").unwrap();
    assert_eq!(loaded.status(), Status::Stopped);
    assert_eq!(loaded.exit_code, Some(0));

    // Step 7: Delete container.
    store.delete("lifecycle-container").unwrap();
    assert!(!store.exists("lifecycle-container"));
}

/// Test bundle with complex Linux configuration.
#[test]
fn test_bundle_with_linux_config() {
    let dir = tempfile::tempdir().unwrap();
    let bundle_path = dir.path().join("linux-bundle");

    // Create a spec with Linux-specific configuration.
    let json = r#"{
        "ociVersion": "1.2.0",
        "root": {
            "path": "rootfs",
            "readonly": false
        },
        "process": {
            "terminal": false,
            "cwd": "/",
            "args": ["sleep", "infinity"],
            "env": ["PATH=/usr/bin"],
            "user": {
                "uid": 1000,
                "gid": 1000,
                "additionalGids": [100, 200]
            },
            "capabilities": {
                "bounding": ["CAP_NET_BIND_SERVICE"],
                "effective": ["CAP_NET_BIND_SERVICE"],
                "inheritable": [],
                "permitted": ["CAP_NET_BIND_SERVICE"],
                "ambient": []
            },
            "rlimits": [
                {"type": "RLIMIT_NOFILE", "soft": 1024, "hard": 4096}
            ],
            "noNewPrivileges": true
        },
        "linux": {
            "namespaces": [
                {"type": "pid"},
                {"type": "network"},
                {"type": "mount"},
                {"type": "ipc"},
                {"type": "uts"}
            ],
            "resources": {
                "memory": {
                    "limit": 536870912,
                    "reservation": 268435456
                },
                "cpu": {
                    "shares": 512,
                    "quota": 50000,
                    "period": 100000
                },
                "pids": {
                    "limit": 100
                }
            },
            "maskedPaths": ["/proc/kcore", "/proc/latency_stats"],
            "readonlyPaths": ["/proc/sys", "/proc/sysrq-trigger"]
        },
        "mounts": [
            {
                "destination": "/proc",
                "type": "proc",
                "source": "proc",
                "options": ["nosuid", "noexec", "nodev"]
            },
            {
                "destination": "/tmp",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "nodev", "mode=1777"]
            }
        ]
    }"#;

    let spec: Spec = serde_json::from_str(json).unwrap();
    let _bundle = Bundle::create(&bundle_path, spec).unwrap();

    // Verify the bundle was created correctly.
    let loaded = Bundle::load(&bundle_path).unwrap();
    let spec = loaded.spec();

    // Verify Linux config.
    let linux = spec.linux.as_ref().unwrap();
    assert_eq!(linux.namespaces.len(), 5);
    assert_eq!(linux.masked_paths.len(), 2);
    assert_eq!(linux.readonly_paths.len(), 2);

    // Verify resources.
    let resources = linux.resources.as_ref().unwrap();
    let memory = resources.memory.as_ref().unwrap();
    assert_eq!(memory.limit, Some(536_870_912));

    let cpu = resources.cpu.as_ref().unwrap();
    assert_eq!(cpu.shares, Some(512));

    // Verify process.
    let process = spec.process.as_ref().unwrap();
    assert!(process.no_new_privileges);
    assert_eq!(process.rlimits.len(), 1);

    let caps = process.capabilities.as_ref().unwrap();
    assert!(caps.bounding.contains(&"CAP_NET_BIND_SERVICE".to_string()));
}

/// Test hooks integration with bundle and state.
#[test]
fn test_hooks_integration() {
    let dir = tempfile::tempdir().unwrap();
    let bundle_path = dir.path().join("hooks-bundle");

    // Create bundle with hooks.
    let mut spec = Spec::default_linux();
    spec.hooks = Some(Hooks {
        create_runtime: vec![
            Hook::new("/usr/bin/setup-network")
                .with_args(vec![
                    "setup-network".to_string(),
                    "--type=bridge".to_string(),
                ])
                .with_timeout(30),
        ],
        poststart: vec![
            Hook::new("/usr/bin/notify")
                .with_env(vec!["NOTIFY_SOCKET=/run/notify.sock".to_string()]),
        ],
        poststop: vec![Hook::new("/usr/bin/cleanup")],
        ..Default::default()
    });

    let bundle = Bundle::create(&bundle_path, spec).unwrap();

    // Verify hooks were saved.
    let loaded = Bundle::load(&bundle_path).unwrap();
    let hooks = loaded.spec().hooks.as_ref().unwrap();

    assert_eq!(hooks.create_runtime.len(), 1);
    assert_eq!(hooks.create_runtime[0].timeout, Some(30));

    assert_eq!(hooks.poststart.len(), 1);
    assert!(!hooks.poststart[0].env.is_empty());

    assert_eq!(hooks.poststop.len(), 1);

    // Validate hooks.
    assert!(hooks.validate().is_ok());

    // Test hook context creation.
    let state = arcbox_oci::State::new("hook-test".to_string(), bundle.path().to_path_buf());
    let context = HookContext::new(state, bundle.path().to_path_buf());

    let state_json = context.state_json().unwrap();
    assert!(state_json.contains("hook-test"));
}

/// Test multiple containers in state store.
#[test]
fn test_multiple_containers_state_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = StateStore::new(dir.path()).unwrap();

    // Create multiple containers.
    let container_names = vec!["web-1", "web-2", "db-1", "cache-1"];

    for name in &container_names {
        let mut state = ContainerState::new(
            name.to_string(),
            PathBuf::from("/bundles").join(name),
            PathBuf::from("/rootfs").join(name),
        );
        state.name = Some(format!("{}-container", name));
        store.save(&state).unwrap();
    }

    // List all containers.
    let ids = store.list().unwrap();
    assert_eq!(ids.len(), 4);

    // Verify all exist.
    for name in &container_names {
        assert!(store.exists(name));
    }

    // Load all states.
    let states = store.list_states().unwrap();
    assert_eq!(states.len(), 4);

    // Delete some.
    store.delete("web-1").unwrap();
    store.delete("cache-1").unwrap();

    let ids = store.list().unwrap();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&"web-2".to_string()));
    assert!(ids.contains(&"db-1".to_string()));
}

/// Test bundle modification and reload.
#[test]
fn test_bundle_modification_workflow() {
    let dir = tempfile::tempdir().unwrap();
    let bundle_path = dir.path().join("modify-bundle");

    // Create initial bundle.
    let bundle = BundleBuilder::new()
        .hostname("original")
        .args(vec!["sh".to_string()])
        .build(&bundle_path)
        .unwrap();

    assert_eq!(bundle.spec().hostname, Some("original".to_string()));

    // Modify and save.
    let mut bundle = Bundle::load(&bundle_path).unwrap();
    bundle.spec_mut().hostname = Some("modified".to_string());
    bundle.spec_mut().domainname = Some("example.com".to_string());

    if let Some(ref mut process) = bundle.spec_mut().process {
        process.args = vec!["nginx".to_string()];
    }

    bundle.save().unwrap();

    // Reload and verify.
    let reloaded = Bundle::load(&bundle_path).unwrap();
    assert_eq!(reloaded.spec().hostname, Some("modified".to_string()));
    assert_eq!(reloaded.spec().domainname, Some("example.com".to_string()));
    assert_eq!(
        reloaded.spec().process.as_ref().unwrap().args,
        vec!["nginx"]
    );
}

/// Test spec validation error handling.
#[test]
fn test_spec_validation_errors() {
    // Invalid mount destination.
    let json = r#"{
        "ociVersion": "1.2.0",
        "mounts": [{"destination": "relative/path"}]
    }"#;
    assert!(Spec::from_json(json).is_err());

    // Invalid process cwd.
    let json = r#"{
        "ociVersion": "1.2.0",
        "process": {"cwd": "relative"}
    }"#;
    assert!(Spec::from_json(json).is_err());

    // Empty OCI version.
    let json = r#"{"ociVersion": ""}"#;
    assert!(Spec::from_json(json).is_err());

    // Empty root path.
    let json = r#"{
        "ociVersion": "1.2.0",
        "root": {"path": ""}
    }"#;
    assert!(Spec::from_json(json).is_err());
}

/// Test state transition error handling.
#[test]
fn test_state_transition_errors() {
    let mut state = ContainerState::new(
        "transition-test".to_string(),
        PathBuf::from("/bundle"),
        PathBuf::from("/rootfs"),
    );

    // Cannot go from Creating to Running directly.
    let result = state.oci_state.clone();
    let mut cloned = result;
    assert!(cloned.transition_to(Status::Running).is_err());

    // Valid: Creating -> Created.
    state.mark_created().unwrap();

    // Cannot go from Created back to Creating.
    assert!(state.oci_state.transition_to(Status::Creating).is_err());
}

/// Test complete OCI spec roundtrip.
#[test]
fn test_oci_spec_complete_roundtrip() {
    let dir = tempfile::tempdir().unwrap();

    // Create a comprehensive spec.
    let mut spec = Spec::default_linux();
    spec.hostname = Some("roundtrip-test".to_string());
    spec.domainname = Some("test.local".to_string());

    spec.annotations = HashMap::from([
        (
            "org.opencontainers.image.authors".to_string(),
            "Test".to_string(),
        ),
        ("custom.annotation".to_string(), "value".to_string()),
    ]);

    spec.mounts.push(Mount {
        destination: "/data".to_string(),
        source: Some("/host/data".to_string()),
        mount_type: Some("bind".to_string()),
        options: Some(vec!["rbind".to_string(), "ro".to_string()]),
        ..Default::default()
    });

    // Save to file.
    let spec_path = dir.path().join("config.json");
    spec.save(&spec_path).unwrap();

    // Load from file.
    let loaded = Spec::load(&spec_path).unwrap();

    // Verify all fields.
    assert_eq!(loaded.oci_version, spec.oci_version);
    assert_eq!(loaded.hostname, spec.hostname);
    assert_eq!(loaded.domainname, spec.domainname);
    assert_eq!(loaded.annotations.len(), 2);
    assert!(loaded.mounts.iter().any(|m| m.destination == "/data"));
}

/// Test error types.
#[test]
fn test_error_types() {
    let dir = tempfile::tempdir().unwrap();
    let store = StateStore::new(dir.path()).unwrap();

    // ContainerNotFound.
    let result = store.load("nonexistent");
    assert!(matches!(result, Err(OciError::ContainerNotFound(_))));

    // BundleNotFound.
    let result = Bundle::load("/nonexistent/bundle");
    assert!(matches!(result, Err(OciError::BundleNotFound(_))));

    // ConfigNotFound.
    let empty_dir = dir.path().join("empty");
    fs::create_dir(&empty_dir).unwrap();
    let result = Bundle::load(&empty_dir);
    assert!(matches!(result, Err(OciError::ConfigNotFound(_))));
}

/// Test bundle utilities.
#[test]
fn test_bundle_utilities() {
    let dir = tempfile::tempdir().unwrap();

    // Create several bundles.
    for i in 1..=5 {
        let path = dir.path().join(format!("bundle-{i}"));
        BundleBuilder::new()
            .hostname(format!("container-{i}"))
            .build(&path)
            .unwrap();
    }

    // Create non-bundle directories.
    fs::create_dir(dir.path().join("not-bundle-1")).unwrap();
    fs::create_dir(dir.path().join("not-bundle-2")).unwrap();

    // Find bundles.
    let bundles = arcbox_oci::bundle::utils::find_bundles(dir.path()).unwrap();
    assert_eq!(bundles.len(), 5);

    // Check is_bundle.
    assert!(arcbox_oci::bundle::utils::is_bundle(
        dir.path().join("bundle-1")
    ));
    assert!(!arcbox_oci::bundle::utils::is_bundle(
        dir.path().join("not-bundle-1")
    ));
}

/// Test container state with all metadata.
#[test]
fn test_container_state_full_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let store = StateStore::new(dir.path()).unwrap();

    let mut state = ContainerState::new(
        "metadata-test".to_string(),
        PathBuf::from("/var/lib/arcbox/bundles/metadata-test"),
        PathBuf::from("/var/lib/arcbox/rootfs/metadata-test"),
    );

    // Set all metadata.
    state.name = Some("my-web-server".to_string());
    state.image = Some("nginx:alpine".to_string());
    state
        .oci_state
        .annotations
        .insert("io.kubernetes.pod.name".to_string(), "web-pod".to_string());

    // Lifecycle.
    state.mark_created().unwrap();
    state.mark_started(54321).unwrap();

    store.save(&state).unwrap();

    // Reload and verify.
    let loaded = store.load("metadata-test").unwrap();

    assert_eq!(loaded.name, Some("my-web-server".to_string()));
    assert_eq!(loaded.image, Some("nginx:alpine".to_string()));
    assert_eq!(loaded.status(), Status::Running);
    assert_eq!(loaded.oci_state.pid, Some(54321));
    assert!(loaded.started.is_some());
    assert!(
        loaded
            .oci_state
            .annotations
            .contains_key("io.kubernetes.pod.name")
    );
}
