//! Docker API integration tests.

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd and docker CLI"]
async fn e2e_docker_run_echo() {
    let output = tokio::process::Command::new("docker")
        .args([
            "--context",
            "arcbox",
            "run",
            "--rm",
            "alpine",
            "echo",
            "e2e-smoke-test",
        ])
        .output()
        .await
        .expect("docker CLI not found");

    assert!(
        output.status.success(),
        "docker run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.trim().contains("e2e-smoke-test"));
}

#[tokio::test]
#[ignore = "requires running daemon with guest dockerd and docker CLI"]
async fn e2e_docker_buildx_build() {
    let tmp = tempfile::tempdir().unwrap();
    let dockerfile = tmp.path().join("Dockerfile");
    tokio::fs::write(&dockerfile, "FROM alpine:latest\nRUN echo built\n")
        .await
        .unwrap();

    let output = tokio::process::Command::new("docker")
        .args([
            "--context",
            "arcbox",
            "buildx",
            "build",
            "--no-cache",
            "-t",
            "arcbox-e2e-smoke:latest",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .await
        .expect("docker CLI not found");

    assert!(
        output.status.success(),
        "docker buildx build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
