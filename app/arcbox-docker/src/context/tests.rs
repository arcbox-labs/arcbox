use super::*;
use tempfile::tempdir;

#[test]
fn test_context_hash() {
    // Docker uses SHA256 of the context name.
    let hash = DockerContextManager::context_hash("arcbox");
    assert_eq!(hash.len(), 64); // SHA256 produces 64 hex chars
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_create_and_remove_context() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("docker.sock");
    let docker_config_dir = temp_dir.path().join(".docker");

    let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

    // Initially no context.
    assert!(!manager.context_exists());

    // Create context.
    manager.create_context().unwrap();
    assert!(manager.context_exists());

    // Verify meta.json content.
    let meta_path = manager.context_meta_path();
    let meta_content = fs::read_to_string(&meta_path).unwrap();
    let meta: ContextMeta = serde_json::from_str(&meta_content).unwrap();
    assert_eq!(meta.name, "arcbox");
    assert!(meta.endpoints.docker.host.starts_with("unix://"));

    // Remove context.
    manager.remove_context().unwrap();
    assert!(!manager.context_exists());
}

#[test]
fn test_set_and_restore_default() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("docker.sock");
    let docker_config_dir = temp_dir.path().join(".docker");

    let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

    // Create context first.
    manager.create_context().unwrap();

    // Set up an existing default context.
    let config = DockerConfig {
        current_context: Some("desktop-linux".to_string()),
        ..DockerConfig::default()
    };
    manager.write_docker_config(&config).unwrap();

    // Set arcbox as default.
    manager.set_default().unwrap();
    assert!(manager.is_default().unwrap());
    assert_eq!(
        manager.current_context().unwrap(),
        Some("arcbox".to_string())
    );

    // Restore previous default.
    manager.restore_default().unwrap();
    assert!(!manager.is_default().unwrap());
    assert_eq!(
        manager.current_context().unwrap(),
        Some("desktop-linux".to_string())
    );
}

#[test]
fn test_enable_disable() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("docker.sock");
    let docker_config_dir = temp_dir.path().join(".docker");

    let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

    // Enable creates context and sets default.
    manager.enable().unwrap();
    assert!(manager.context_exists());
    assert!(manager.is_default().unwrap());

    // Disable restores previous default.
    manager.disable().unwrap();
    assert!(manager.context_exists()); // Context still exists
    assert!(!manager.is_default().unwrap()); // But not default
}

#[test]
fn test_status() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("docker.sock");
    let docker_config_dir = temp_dir.path().join(".docker");

    let manager = DockerContextManager::with_config_dir(socket_path.clone(), docker_config_dir);

    let status = manager.status();
    assert!(!status.context_exists);
    assert!(!status.is_default);
    assert_eq!(status.socket_path, socket_path);
    assert!(!status.socket_exists);

    // Create socket file and context.
    fs::write(&socket_path, "").unwrap();
    manager.enable().unwrap();

    let status = manager.status();
    assert!(status.context_exists);
    assert!(status.is_default);
    assert!(status.socket_exists);
}

#[test]
fn test_preserves_other_config_fields() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("docker.sock");
    let docker_config_dir = temp_dir.path().join(".docker");
    fs::create_dir_all(&docker_config_dir).unwrap();

    // Create a config with extra fields.
    let config_path = docker_config_dir.join("config.json");
    let initial_config = r#"{
        "currentContext": "desktop-linux",
        "credsStore": "osxkeychain",
        "auths": {
            "https://index.docker.io/v1/": {}
        }
    }"#;
    fs::write(&config_path, initial_config).unwrap();

    let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);
    manager.create_context().unwrap();
    manager.set_default().unwrap();

    // Read back and verify other fields are preserved.
    let updated_config = fs::read_to_string(&config_path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&updated_config).unwrap();

    assert_eq!(config["currentContext"], "arcbox");
    assert_eq!(config["credsStore"], "osxkeychain");
    assert!(config["auths"].is_object());
}

#[test]
fn test_create_context_is_idempotent() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("docker.sock");
    let docker_config_dir = temp_dir.path().join(".docker");

    let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

    // Create context twice - should not fail.
    manager.create_context().unwrap();
    let first_meta = fs::read_to_string(manager.context_meta_path()).unwrap();

    manager.create_context().unwrap();
    let second_meta = fs::read_to_string(manager.context_meta_path()).unwrap();

    // Content should be identical.
    assert_eq!(first_meta, second_meta);
}

#[test]
fn test_remove_default_context_restores_previous() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("docker.sock");
    let docker_config_dir = temp_dir.path().join(".docker");

    let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

    // Set up: create context with a previous default.
    let config = DockerConfig {
        current_context: Some("orbstack".to_string()),
        ..DockerConfig::default()
    };
    manager.create_context().unwrap();
    manager.write_docker_config(&config).unwrap();
    manager.set_default().unwrap();

    assert!(manager.is_default().unwrap());

    // Remove context - should restore orbstack as default.
    manager.remove_context().unwrap();

    assert!(!manager.context_exists());
    assert_eq!(
        manager.current_context().unwrap(),
        Some("orbstack".to_string())
    );
}

#[test]
fn test_set_default_without_previous_context() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("docker.sock");
    let docker_config_dir = temp_dir.path().join(".docker");

    let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

    // No config.json exists - fresh install scenario.
    manager.create_context().unwrap();
    manager.set_default().unwrap();

    assert!(manager.is_default().unwrap());

    // Restore should clear the context (no previous).
    manager.restore_default().unwrap();
    assert!(manager.current_context().unwrap().is_none());
}

#[test]
fn test_multiple_enable_disable_cycles() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("docker.sock");
    let docker_config_dir = temp_dir.path().join(".docker");

    let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

    // Set up initial context.
    let config = DockerConfig {
        current_context: Some("default".to_string()),
        ..DockerConfig::default()
    };
    fs::create_dir_all(manager.docker_config_dir()).unwrap();
    manager.write_docker_config(&config).unwrap();

    // Cycle 1.
    manager.enable().unwrap();
    assert!(manager.is_default().unwrap());
    manager.disable().unwrap();
    assert_eq!(
        manager.current_context().unwrap(),
        Some("default".to_string())
    );

    // Cycle 2.
    manager.enable().unwrap();
    assert!(manager.is_default().unwrap());
    manager.disable().unwrap();
    assert_eq!(
        manager.current_context().unwrap(),
        Some("default".to_string())
    );

    // Cycle 3.
    manager.enable().unwrap();
    assert!(manager.is_default().unwrap());
    manager.disable().unwrap();
    assert_eq!(
        manager.current_context().unwrap(),
        Some("default".to_string())
    );
}

#[test]
fn test_set_default_fails_without_context() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("docker.sock");
    let docker_config_dir = temp_dir.path().join(".docker");

    let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

    // Try to set default without creating context first.
    let result = manager.set_default();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("does not exist"));
}

#[test]
fn test_disable_when_not_default_is_noop() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("docker.sock");
    let docker_config_dir = temp_dir.path().join(".docker");

    let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

    // Create context but don't set as default.
    manager.create_context().unwrap();
    assert!(!manager.is_default().unwrap());

    // Disable should succeed but do nothing.
    manager.disable().unwrap();
    assert!(!manager.is_default().unwrap());
}

#[test]
fn test_remove_nonexistent_context_is_noop() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("docker.sock");
    let docker_config_dir = temp_dir.path().join(".docker");

    let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

    // Remove context that doesn't exist - should not fail.
    manager.remove_context().unwrap();
    assert!(!manager.context_exists());
}

#[test]
fn test_handles_empty_config_json() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("docker.sock");
    let docker_config_dir = temp_dir.path().join(".docker");
    fs::create_dir_all(&docker_config_dir).unwrap();

    // Create empty config.json.
    let config_path = docker_config_dir.join("config.json");
    fs::write(&config_path, "{}").unwrap();

    let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

    // Should handle empty config gracefully.
    assert!(manager.current_context().unwrap().is_none());
    assert!(!manager.is_default().unwrap());

    // Enable should work.
    manager.enable().unwrap();
    assert!(manager.is_default().unwrap());
}

#[test]
fn test_context_meta_json_format() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("test.sock");
    let docker_config_dir = temp_dir.path().join(".docker");

    let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);
    manager.create_context().unwrap();

    // Read and verify the meta.json structure matches Docker's format.
    let meta_content = fs::read_to_string(manager.context_meta_path()).unwrap();
    let meta: serde_json::Value = serde_json::from_str(&meta_content).unwrap();

    // Docker expects PascalCase keys.
    assert!(meta.get("Name").is_some());
    assert!(meta.get("Metadata").is_some());
    assert!(meta.get("Endpoints").is_some());

    // Verify nested structure.
    let endpoints = meta.get("Endpoints").unwrap();
    let docker_endpoint = endpoints.get("docker").unwrap();
    assert!(docker_endpoint.get("Host").is_some());
    assert!(docker_endpoint.get("SkipTLSVerify").is_some());

    // Verify Host format.
    let host = docker_endpoint.get("Host").unwrap().as_str().unwrap();
    assert!(host.starts_with("unix://"));
    assert!(host.contains("test.sock"));
}

#[test]
fn test_context_hash_is_deterministic() {
    // Same context name should always produce the same hash.
    let hash1 = DockerContextManager::context_hash("arcbox");
    let hash2 = DockerContextManager::context_hash("arcbox");
    let hash3 = DockerContextManager::context_hash("arcbox");

    assert_eq!(hash1, hash2);
    assert_eq!(hash2, hash3);

    // Different names produce different hashes.
    let other_hash = DockerContextManager::context_hash("other-context");
    assert_ne!(hash1, other_hash);
}

#[test]
fn test_context_directory_structure() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("docker.sock");
    let docker_config_dir = temp_dir.path().join(".docker");

    let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir.clone());
    manager.create_context().unwrap();

    // Verify Docker-compatible directory structure.
    let contexts_base = docker_config_dir.join("contexts");
    let meta_dir = contexts_base.join("meta");

    assert!(contexts_base.exists());
    assert!(meta_dir.exists());

    // Context should be in a hash-named directory.
    let hash = DockerContextManager::context_hash(ARCBOX_CONTEXT_NAME);
    let hashed_dir = meta_dir.join(&hash);
    assert!(hashed_dir.exists());

    // meta.json should exist in the context directory.
    let meta_path = hashed_dir.join("meta.json");
    assert!(meta_path.exists());
}

#[test]
fn test_full_lifecycle() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("docker.sock");
    let docker_config_dir = temp_dir.path().join(".docker");

    let manager = DockerContextManager::with_config_dir(socket_path.clone(), docker_config_dir);

    // 1. Initial state - nothing exists.
    assert!(!manager.context_exists());
    let status = manager.status();
    assert!(!status.context_exists);
    assert!(!status.is_default);

    // 2. Enable integration.
    manager.enable().unwrap();
    assert!(manager.context_exists());
    assert!(manager.is_default().unwrap());

    // 3. Create socket file (simulating daemon running).
    fs::write(&socket_path, "").unwrap();
    let status = manager.status();
    assert!(status.socket_exists);

    // 4. Disable integration.
    manager.disable().unwrap();
    assert!(manager.context_exists()); // Context still exists.
    assert!(!manager.is_default().unwrap());

    // 5. Re-enable.
    manager.enable().unwrap();
    assert!(manager.is_default().unwrap());

    // 6. Remove completely.
    manager.remove_context().unwrap();
    assert!(!manager.context_exists());
    assert!(!manager.is_default().unwrap());
}

#[test]
fn test_switching_from_orbstack() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("docker.sock");
    let docker_config_dir = temp_dir.path().join(".docker");
    fs::create_dir_all(&docker_config_dir).unwrap();

    // Simulate existing OrbStack setup.
    let config_path = docker_config_dir.join("config.json");
    let orbstack_config = r#"{
        "currentContext": "orbstack",
        "credsStore": "osxkeychain",
        "auths": {},
        "plugins": {
            "debug": {"hooks": "exec"}
        }
    }"#;
    fs::write(&config_path, orbstack_config).unwrap();

    let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

    // Enable ArcBox.
    manager.enable().unwrap();
    assert!(manager.is_default().unwrap());

    // Verify OrbStack config is preserved.
    let updated_config = fs::read_to_string(&config_path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&updated_config).unwrap();
    assert_eq!(config["currentContext"], "arcbox");
    assert_eq!(config["credsStore"], "osxkeychain");
    assert!(config["plugins"].is_object());

    // Disable - should restore OrbStack.
    manager.disable().unwrap();
    let restored_config = fs::read_to_string(&config_path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&restored_config).unwrap();
    assert_eq!(config["currentContext"], "orbstack");
}

#[test]
fn test_socket_path_with_spaces() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("path with spaces/docker.sock");
    let docker_config_dir = temp_dir.path().join(".docker");

    let manager = DockerContextManager::with_config_dir(socket_path.clone(), docker_config_dir);
    manager.create_context().unwrap();

    // Verify the socket path is correctly stored.
    let meta_content = fs::read_to_string(manager.context_meta_path()).unwrap();
    let meta: ContextMeta = serde_json::from_str(&meta_content).unwrap();

    assert!(meta.endpoints.docker.host.contains("path with spaces"));
    assert_eq!(
        meta.endpoints.docker.host,
        format!("unix://{}", socket_path.display())
    );
}

#[test]
fn test_context_status_display() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("docker.sock");
    let docker_config_dir = temp_dir.path().join(".docker");

    let manager = DockerContextManager::with_config_dir(socket_path, docker_config_dir);

    // Get status and verify Display impl.
    let status = manager.status();
    let display = format!("{status}");

    assert!(display.contains("Context exists:"));
    assert!(display.contains("Is default:"));
    assert!(display.contains("Socket path:"));
    assert!(display.contains("Socket exists:"));
}
