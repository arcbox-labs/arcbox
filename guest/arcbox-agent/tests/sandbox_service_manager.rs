#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::time::Duration;

use arcbox_agent::sandbox::SandboxService;
use arcbox_protocol::sandbox_v1::{
    CreateSandboxRequest, InspectSandboxRequest, ListSandboxesRequest, NetworkSpec,
    RemoveSandboxRequest, RunOutput, RunRequest, StopSandboxRequest,
};
use arcbox_vm::VmmConfig;
use arcbox_vm::config::{DefaultVmConfig, FirecrackerConfig, GrpcConfig, NetworkConfig};
use prost::Message;

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("required env var is missing: {name}"))
}

fn test_config() -> VmmConfig {
    let firecracker = required_env("FC_BINARY");
    let kernel = required_env("FC_KERNEL");
    let rootfs = required_env("FC_ROOTFS");

    let data_dir = format!("/tmp/arcbox-agent-test-{}", std::process::id());

    VmmConfig {
        firecracker: FirecrackerConfig {
            binary: firecracker,
            jailer: None,
            data_dir: data_dir.clone(),
            log_level: Some("Error".to_string()),
            no_seccomp: true,
            seccomp_filter: None,
            http_api_max_payload_size: None,
            mmds_size_limit: None,
            socket_timeout_secs: Some(15),
        },
        network: NetworkConfig {
            // Bridge is ignored for mode=none, keep explicit for clarity.
            bridge: String::new(),
            cidr: "172.31.0.0/16".to_string(),
            gateway: "172.31.0.1".to_string(),
            dns: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
        },
        grpc: GrpcConfig {
            unix_socket: format!("{data_dir}/vmm.sock"),
            tcp_addr: String::new(),
        },
        defaults: DefaultVmConfig {
            vcpus: 1,
            memory_mib: 256,
            kernel,
            rootfs,
            boot_args: "console=ttyS0 reboot=k panic=1 pci=off init=/sbin/vm-agent".to_string(),
        },
    }
}

async fn cleanup_sandbox(service: &SandboxService, sandbox_id: &str) {
    let remove_payload = RemoveSandboxRequest {
        id: sandbox_id.to_string(),
        force: true,
    }
    .encode_to_vec();
    let _ = service.remove(&remove_payload).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires kvm, firecracker assets, and root privileges"]
async fn sandbox_service_calls_sandbox_manager() {
    let service = SandboxService::new(test_config()).expect("failed to initialize sandbox service");

    let create_req = CreateSandboxRequest {
        id: String::new(),
        labels: HashMap::from([("suite".to_string(), "svc-manager".to_string())]),
        kernel: String::new(),
        rootfs: String::new(),
        boot_args: String::new(),
        limits: None,
        image: String::new(),
        cmd: Vec::new(),
        env: HashMap::new(),
        working_dir: String::new(),
        user: String::new(),
        mounts: Vec::new(),
        network: Some(NetworkSpec {
            mode: "none".to_string(),
        }),
        ttl_seconds: 0,
        ssh_public_key: None,
    };
    let create_payload = create_req.encode_to_vec();
    let created = service
        .create(&create_payload)
        .await
        .expect("sandbox create should succeed");
    assert!(!created.id.is_empty(), "create returned empty sandbox id");
    let sandbox_id = created.id.clone();

    let ready_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let inspect_req = InspectSandboxRequest {
            id: sandbox_id.clone(),
        };
        let inspect_payload = inspect_req.encode_to_vec();
        let info = service.inspect(&inspect_payload).expect("inspect failed");

        if info.state == "ready" {
            break;
        }
        if info.state == "failed" {
            cleanup_sandbox(&service, &sandbox_id).await;
            panic!("sandbox entered failed state: {}", info.error);
        }
        if tokio::time::Instant::now() >= ready_deadline {
            cleanup_sandbox(&service, &sandbox_id).await;
            panic!("timeout waiting for sandbox to become ready");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let list_payload = ListSandboxesRequest {
        state: String::new(),
        labels: HashMap::new(),
    }
    .encode_to_vec();
    let list = service.list(&list_payload).expect("list failed");
    assert!(
        list.sandboxes.iter().any(|s| s.id == sandbox_id),
        "created sandbox not found in list"
    );

    let run_payload = RunRequest {
        id: sandbox_id.clone(),
        cmd: vec![
            "/bin/sh".to_string(),
            "-lc".to_string(),
            "echo sandbox-service-manager".to_string(),
        ],
        env: HashMap::new(),
        working_dir: String::new(),
        user: String::new(),
        tty: false,
        timeout_seconds: 30,
    }
    .encode_to_vec();

    let mut run_rx = service
        .run(&run_payload)
        .await
        .expect("run should start successfully");

    let mut got_done = false;
    while let Some(frame) = run_rx.recv().await {
        let out = RunOutput::decode(frame.as_slice()).expect("invalid RunOutput frame");
        if out.done {
            got_done = true;
            assert_eq!(out.exit_code, 0, "run exited with non-zero code");
            break;
        }
    }
    assert!(got_done, "run stream ended without done=true frame");

    let stop_payload = StopSandboxRequest {
        id: sandbox_id.clone(),
        timeout_seconds: 20,
    }
    .encode_to_vec();
    service.stop(&stop_payload).await.expect("stop failed");

    let remove_payload = RemoveSandboxRequest {
        id: sandbox_id,
        force: true,
    }
    .encode_to_vec();
    service
        .remove(&remove_payload)
        .await
        .expect("remove failed");
}
