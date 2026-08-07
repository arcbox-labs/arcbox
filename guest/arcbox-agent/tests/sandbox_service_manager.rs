#![cfg(target_os = "linux")]

use std::time::Duration;

use arcbox_agent::error::SandboxError;
use arcbox_agent::sandbox::SandboxService;
use arcbox_connect::sandbox_v1::{
    CreateSandboxRequest, InspectSandboxRequest, ListSandboxesRequest, NetworkMode, NetworkSpec,
    RemoveSandboxRequest, SandboxState, StartExecutionRequest, StopSandboxRequest,
    WaitExecutionRequest, exit_status,
};
use arcbox_vm::VmmConfig;
use arcbox_vm::config::{DefaultVmConfig, FirecrackerConfig, GrpcConfig, NetworkConfig};
use buffa::Message;

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
            sandbox_datapath: arcbox_vm::config::SandboxDatapath::default(),
            // Direct mode cannot restore (and so never pools); keep the
            // test run free of background pre-warm spawns regardless.
            pool_size: 0,
        },
        network: NetworkConfig {
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
    let payload = RemoveSandboxRequest {
        id: sandbox_id.to_string(),
        force: true,
        ..Default::default()
    }
    .encode_to_vec();
    let _ = service.remove(&payload).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires kvm, firecracker assets, and root privileges"]
async fn sandbox_service_calls_sandbox_manager() {
    let service = SandboxService::new(test_config()).expect("failed to initialize sandbox service");

    // Empty template = the built-in busybox image.
    let create_req = CreateSandboxRequest {
        id: "svc-manager".to_string(),
        labels: std::iter::once(("suite".to_string(), "svc-manager".to_string())).collect(),
        network: NetworkSpec {
            mode: NetworkMode::None.into(),
            ..Default::default()
        }
        .into(),
        ..Default::default()
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
            ..Default::default()
        };
        let inspect_payload = inspect_req.encode_to_vec();
        let info = service.inspect(&inspect_payload).expect("inspect failed");

        if info.state == SandboxState::Ready {
            break;
        }
        if info.state == SandboxState::Failed {
            cleanup_sandbox(&service, &sandbox_id).await;
            panic!("sandbox entered failed state: {}", info.error);
        }
        if tokio::time::Instant::now() >= ready_deadline {
            cleanup_sandbox(&service, &sandbox_id).await;
            panic!("timeout waiting for sandbox to become ready");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let list_payload = ListSandboxesRequest::default().encode_to_vec();
    let list = service.list(&list_payload).expect("list failed");
    assert!(
        list.sandboxes.iter().any(|s| s.id == sandbox_id),
        "created sandbox not found in list"
    );

    let start_payload = StartExecutionRequest {
        sandbox_id: sandbox_id.clone(),
        execution_id: "svc-manager-echo".to_string(),
        cmd: vec![
            "/bin/sh".to_string(),
            "-lc".to_string(),
            "echo sandbox-service-manager".to_string(),
        ],
        timeout_seconds: 30,
        ..Default::default()
    }
    .encode_to_vec();
    let started = service
        .start_execution(&start_payload)
        .await
        .expect("start_execution should succeed");
    assert_eq!(started.id, "svc-manager-echo");

    let wait_payload = WaitExecutionRequest {
        sandbox_id: sandbox_id.clone(),
        execution_id: started.id.clone(),
        timeout_seconds: 30,
        ..Default::default()
    }
    .encode_to_vec();
    let finished = service
        .wait_execution(&wait_payload)
        .await
        .expect("wait_execution failed");
    let status = finished
        .exit_status
        .into_option()
        .and_then(|s| s.status)
        .expect("execution should report an exit status");
    assert_eq!(
        status,
        exit_status::Status::Code(0),
        "echo exited with a non-zero status"
    );
    assert!(
        finished.stdout_len > 0,
        "execution produced no stdout bytes"
    );

    let stop_payload = StopSandboxRequest {
        id: sandbox_id.clone(),
        timeout_seconds: 20,
        ..Default::default()
    }
    .encode_to_vec();
    service.stop(&stop_payload).await.expect("stop failed");

    let retry_error = match service.create(&create_payload).await {
        Err(error) => error,
        Ok(_) => panic!("stopped sandbox must not replay its stale Create response"),
    };
    assert!(matches!(retry_error, SandboxError::AlreadyExists(_)));

    let remove_payload = RemoveSandboxRequest {
        id: sandbox_id,
        force: true,
        ..Default::default()
    }
    .encode_to_vec();
    service
        .remove(&remove_payload)
        .await
        .expect("remove failed");
}
