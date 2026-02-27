#!/bin/bash
# Boot assets integration test script
# Tests kernel boot, vsock connectivity, and agent functionality

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TEST_DIR="/tmp/arcbox-boot-test-$$"
BOOT_ASSETS_VERSION_DEFAULT="$(awk -F '\"' '/pub const BOOT_ASSET_VERSION/ {print $2; exit}' "$PROJECT_DIR/crates/arcbox-core/src/boot_assets.rs")"
if [[ -z "$BOOT_ASSETS_VERSION_DEFAULT" ]]; then
    echo "Failed to resolve BOOT_ASSET_VERSION from crates/arcbox-core/src/boot_assets.rs" >&2
    exit 1
fi
BOOT_ASSETS_VERSION="${ARCBOX_BOOT_ASSET_VERSION:-$BOOT_ASSETS_VERSION_DEFAULT}"
TEST_LABEL="arcbox.e2e.run=$$"
GUEST_DOCKER_VSOCK_PORT="${ARCBOX_GUEST_DOCKER_VSOCK_PORT:-2375}"

# Test result tracking
RESULT_VM_BOOT="SKIP"
RESULT_VSOCK="SKIP"
RESULT_AGENT="SKIP"
RESULT_CONTAINER_CREATE="SKIP"
RESULT_CONTAINER_RUN="SKIP"
RESULT_BACKGROUND_CONTAINER="SKIP"
RESULT_DOCKER_LOGS="SKIP"
RESULT_DOCKER_EXEC="SKIP"
RESULT_STOP_RM="SKIP"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    log_info "Cleaning up..."
    # Remove any test containers created in this run.
    local ids
    ids=$(DOCKER_HOST="unix://$TEST_DIR/docker.sock" docker ps -aq --filter "label=$TEST_LABEL" 2>/dev/null || true)
    if [[ -n "$ids" ]]; then
        DOCKER_HOST="unix://$TEST_DIR/docker.sock" docker rm -f $ids >/dev/null 2>&1 || true
    fi
    pkill -f "arcbox.*daemon.*$TEST_DIR" 2>/dev/null || true
    if [[ -n "${KEEP_TEST_DIR:-}" ]]; then
        log_warn "KEEP_TEST_DIR set, preserving: $TEST_DIR"
    else
        rm -rf "$TEST_DIR"
    fi
}

# Helper: run docker commands against the test socket
dkr() {
    DOCKER_HOST="unix://$TEST_DIR/docker.sock" docker "$@"
}

trap cleanup EXIT

# Check for required files
check_prerequisites() {
    log_info "Checking prerequisites..."

    if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
        log_info "Building latest arcbox release binary..."
        (cd "$PROJECT_DIR" && cargo build --release -p arcbox-cli)
    fi

    # Check for entitlements
    if [[ ! -f "$PROJECT_DIR/target/release/arcbox-daemon" ]]; then
        log_error "arcbox-daemon binary not found at target/release/arcbox-daemon"
        exit 1
    fi

    if ! codesign -d --entitlements :- "$PROJECT_DIR/target/release/arcbox-daemon" 2>/dev/null | grep -q "com.apple.security.virtualization"; then
        log_warn "Binary not signed with virtualization entitlement. Signing..."
        codesign --entitlements "$PROJECT_DIR/tests/resources/entitlements.plist" --force -s - "$PROJECT_DIR/target/release/arcbox-daemon"
    fi

    log_info "Prerequisites OK"
}

# Setup test environment with boot assets
setup_test_env() {
    log_info "Setting up test environment: $TEST_DIR"

    mkdir -p "$TEST_DIR/boot/$BOOT_ASSETS_VERSION"

    # Use development boot assets
    local dev_boot_dir="$PROJECT_DIR/boot-assets/dev"
    local dev_kernel="$dev_boot_dir/kernel"
    local dev_initramfs="$dev_boot_dir/initramfs.cpio.gz"
    local dev_rootfs="$dev_boot_dir/rootfs.squashfs"
    local dev_modloop="$dev_boot_dir/modloop"
    local dev_manifest="$dev_boot_dir/manifest.json"

    if [[ ! -f "$dev_kernel" ]] || [[ ! -f "$dev_initramfs" ]] || [[ ! -f "$dev_rootfs" ]] || [[ ! -f "$dev_modloop" ]] || [[ ! -f "$dev_manifest" ]]; then
        log_warn "Development boot assets incomplete, refreshing..."
        (cd "$PROJECT_DIR" && ./scripts/setup-dev-boot-assets.sh)
    fi

    if [[ -f "$dev_kernel" ]] && [[ -f "$dev_initramfs" ]] && [[ -f "$dev_rootfs" ]] && [[ -f "$dev_modloop" ]] && [[ -f "$dev_manifest" ]]; then
        cp "$dev_kernel" "$TEST_DIR/boot/$BOOT_ASSETS_VERSION/"
        cp "$dev_initramfs" "$TEST_DIR/boot/$BOOT_ASSETS_VERSION/"
        cp "$dev_rootfs" "$TEST_DIR/boot/$BOOT_ASSETS_VERSION/"
        cp "$dev_modloop" "$TEST_DIR/boot/$BOOT_ASSETS_VERSION/"
        cp "$dev_manifest" "$TEST_DIR/boot/$BOOT_ASSETS_VERSION/"
        log_info "Using development boot assets from $dev_boot_dir"
    else
        log_error "Development boot assets not found or incomplete at $dev_boot_dir"
        log_error "Required files: kernel, initramfs.cpio.gz, rootfs.squashfs, modloop, manifest.json"
        log_error "Run: ./scripts/setup-dev-boot-assets.sh"
        exit 1
    fi
}

# Start daemon
start_daemon() {
    log_info "Starting daemon..."

    ARCBOX_BOOT_ASSET_VERSION="$BOOT_ASSETS_VERSION" \
    "$PROJECT_DIR/target/release/arcbox-daemon" \
        --data-dir "$TEST_DIR" \
        --socket "$TEST_DIR/docker.sock" \
        --container-provision bundled-assets \
        --guest-docker-vsock-port "$GUEST_DOCKER_VSOCK_PORT" \
        > "$TEST_DIR/daemon.log" 2>&1 &

    DAEMON_PID=$!
    echo $DAEMON_PID > "$TEST_DIR/daemon.pid"

    sleep 2

    if ! kill -0 $DAEMON_PID 2>/dev/null; then
        log_error "Daemon failed to start"
        cat "$TEST_DIR/daemon.log"
        exit 1
    fi

    log_info "Daemon started (PID: $DAEMON_PID)"
}

# Wait for agent connection (VM starts on-demand during docker pull)
wait_for_agent() {
    log_info "Waiting for agent connection..."

    local timeout=60
    local elapsed=0

    while [[ $elapsed -lt $timeout ]]; do
        if grep -q "Agent is ready" "$TEST_DIR/daemon.log" 2>/dev/null; then
            echo ""
            log_info "Agent connected in ${elapsed}s"
            return 0
        fi
        sleep 1
        ((elapsed++))
        printf "."
    done

    echo ""
    log_error "Agent connection timeout (${timeout}s)"
    log_error "Daemon log:"
    cat "$TEST_DIR/daemon.log"
    return 1
}

# --- Container lifecycle test functions (Phase 1.2 / 1.4) ---

# Test: docker run alpine echo hello
test_container_run() {
    log_info "[test] Container run: docker run alpine echo hello"
    local cid
    cid=$(DOCKER_HOST="unix://$TEST_DIR/docker.sock" timeout 30 docker create --label "$TEST_LABEL" alpine echo hello) || {
        log_error "docker create failed"
        return 1
    }
    cid="${cid%%$'\n'*}"

    if ! DOCKER_HOST="unix://$TEST_DIR/docker.sock" timeout 30 docker start "$cid" >/dev/null; then
        log_error "docker start failed"
        dkr rm -f "$cid" >/dev/null 2>&1 || true
        return 1
    fi

    if ! DOCKER_HOST="unix://$TEST_DIR/docker.sock" timeout 30 docker wait "$cid" >/dev/null; then
        log_error "docker wait failed"
        dkr rm -f "$cid" >/dev/null 2>&1 || true
        return 1
    fi

    local output
    output=$(DOCKER_HOST="unix://$TEST_DIR/docker.sock" timeout 10 docker logs "$cid" 2>&1) || {
        log_error "docker logs failed after wait: $output"
        dkr rm -f "$cid" >/dev/null 2>&1 || true
        return 1
    }

    dkr rm -f "$cid" >/dev/null 2>&1 || true

    if echo "$output" | grep -q "hello"; then
        log_info "container run: OK"
        return 0
    else
        log_error "Expected 'hello' in output, got: $output"
        return 1
    fi
}

# Test: background container visible in docker ps
test_background_container() {
    log_info "[test] Background container: docker run -d + docker ps"

    local cid
    cid=$(DOCKER_HOST="unix://$TEST_DIR/docker.sock" timeout 30 docker run -d --label "$TEST_LABEL" alpine sleep 300) || {
        log_error "docker run -d failed"
        return 1
    }
    cid="${cid%%$'\n'*}"
    log_info "Started background container: ${cid:0:12}"

    sleep 2

    local running
    running=$(DOCKER_HOST="unix://$TEST_DIR/docker.sock" timeout 10 docker inspect -f '{{.State.Running}}' "$cid" 2>&1) || {
        log_error "docker inspect failed: $running"
        dkr rm -f "$cid" >/dev/null 2>&1 || true
        return 1
    }

    if [[ "$running" == "true" ]]; then
        log_info "background container is running: OK"
        dkr stop "$cid" >/dev/null 2>&1 || true
        dkr rm -f "$cid" >/dev/null 2>&1 || true
        return 0
    else
        log_error "Container is not running (inspect output: $running)"
        dkr rm -f "$cid" >/dev/null 2>&1 || true
        return 1
    fi
}

# Test: docker logs
test_docker_logs() {
    log_info "[test] Docker logs: verify container output"

    local cid
    cid=$(DOCKER_HOST="unix://$TEST_DIR/docker.sock" timeout 30 docker run -d --label "$TEST_LABEL" alpine sh -c "echo 'log-output-test'; sleep 10") || {
        log_error "docker run -d for log test failed"
        return 1
    }
    cid="${cid%%$'\n'*}"
    log_info "Started log-test container: ${cid:0:12}"

    local found=0
    local logs_output
    # Retry briefly to avoid race between container start and log flush.
    for _ in {1..10}; do
        logs_output=$(DOCKER_HOST="unix://$TEST_DIR/docker.sock" timeout 10 docker logs "$cid" 2>&1) || {
            log_error "docker logs failed: $logs_output"
            dkr rm -f "$cid" >/dev/null 2>&1 || true
            return 1
        }
        if echo "$logs_output" | grep -q "log-output-test"; then
            found=1
            break
        fi
        sleep 1
    done

    dkr rm -f "$cid" >/dev/null 2>&1 || true

    if [[ $found -eq 1 ]]; then
        log_info "docker logs contains expected output: OK"
        return 0
    else
        log_error "Expected 'log-output-test' in logs, got: $logs_output"
        return 1
    fi
}

# Test: docker exec
test_docker_exec() {
    log_info "[test] Docker exec: run command in running container"

    local cid
    cid=$(DOCKER_HOST="unix://$TEST_DIR/docker.sock" timeout 30 docker run -d --label "$TEST_LABEL" alpine sleep 300) || {
        log_error "docker run -d for exec test failed"
        return 1
    }
    cid="${cid%%$'\n'*}"
    log_info "Started exec-test container: ${cid:0:12}"

    sleep 2

    local exec_output
    exec_output=$(DOCKER_HOST="unix://$TEST_DIR/docker.sock" timeout 10 docker exec "$cid" ls / 2>&1) || {
        log_error "docker exec failed: $exec_output"
        dkr rm -f "$cid" >/dev/null 2>&1 || true
        return 1
    }

    dkr rm -f "$cid" >/dev/null 2>&1 || true

    if echo "$exec_output" | grep -qE "(bin|etc|usr)"; then
        log_info "docker exec ls / succeeded: OK"
        return 0
    else
        log_error "docker exec ls / returned unexpected output: $exec_output"
        return 1
    fi
}

# Test: docker stop + docker rm
test_stop_rm() {
    log_info "[test] Stop/rm: graceful stop and remove"

    local cid
    cid=$(DOCKER_HOST="unix://$TEST_DIR/docker.sock" timeout 30 docker run -d --label "$TEST_LABEL" alpine sleep 300) || {
        log_error "docker run -d for stop test failed"
        return 1
    }
    cid="${cid%%$'\n'*}"
    log_info "Started stop-test container: ${cid:0:12}"

    sleep 2

    if ! DOCKER_HOST="unix://$TEST_DIR/docker.sock" timeout 15 docker stop "$cid" >/dev/null 2>&1; then
        log_error "docker stop failed"
        dkr rm -f "$cid" >/dev/null 2>&1 || true
        return 1
    fi
    log_info "docker stop: OK"

    if ! DOCKER_HOST="unix://$TEST_DIR/docker.sock" timeout 10 docker rm "$cid" >/dev/null 2>&1; then
        log_error "docker rm failed"
        dkr rm -f "$cid" >/dev/null 2>&1 || true
        return 1
    fi
    log_info "docker rm: OK"

    if dkr inspect "$cid" >/dev/null 2>&1; then
        log_error "Container still exists after rm: $cid"
        return 1
    fi

    log_info "Container fully removed: OK"
    return 0
}

# Print summary
print_summary() {
    echo ""
    echo "=========================================="
    echo "Boot Assets Test Summary"
    echo "=========================================="

    local kernel_version
    kernel_version=$(strings "$TEST_DIR/boot/$BOOT_ASSETS_VERSION/kernel" 2>/dev/null | grep -E "^[0-9]+\.[0-9]+\.[0-9]+" | head -1)

    echo "Kernel:     $kernel_version"
    echo "Initramfs:  $(ls -lh "$TEST_DIR/boot/$BOOT_ASSETS_VERSION/initramfs.cpio.gz" | awk '{print $5}')"
    echo "Rootfs:     $(ls -lh "$TEST_DIR/boot/$BOOT_ASSETS_VERSION/rootfs.squashfs" | awk '{print $5}')"
    echo "Modloop:    $(ls -lh "$TEST_DIR/boot/$BOOT_ASSETS_VERSION/modloop" | awk '{print $5}')"
    echo ""

    local pass=0
    local fail=0
    local skip=0
    local total=0

    for result_var in \
        "VM Boot:$RESULT_VM_BOOT" \
        "vsock:$RESULT_VSOCK" \
        "Agent:$RESULT_AGENT" \
        "Container Create:$RESULT_CONTAINER_CREATE" \
        "Container Run:$RESULT_CONTAINER_RUN" \
        "Background Container:$RESULT_BACKGROUND_CONTAINER" \
        "Docker Logs:$RESULT_DOCKER_LOGS" \
        "Docker Exec:$RESULT_DOCKER_EXEC" \
        "Stop/Rm:$RESULT_STOP_RM"; do

        local label="${result_var%%:*}"
        local status="${result_var##*:}"
        ((total++))

        case "$status" in
            PASS) echo -e "  $(printf '%-22s' "$label") ${GREEN}PASS${NC}"; ((pass++)) ;;
            FAIL) echo -e "  $(printf '%-22s' "$label") ${RED}FAIL${NC}"; ((fail++)) ;;
            SKIP) echo -e "  $(printf '%-22s' "$label") ${YELLOW}SKIP${NC}"; ((skip++)) ;;
        esac
    done

    echo ""
    echo -e "Results: ${GREEN}${pass} passed${NC}, ${RED}${fail} failed${NC}, ${YELLOW}${skip} skipped${NC} / ${total} total"
    echo "Log: $TEST_DIR/daemon.log"
    echo "=========================================="

    if [[ $fail -gt 0 ]]; then
        return 1
    fi
    return 0
}

# Main
main() {
    echo "=========================================="
    echo "ArcBox Boot Assets Integration Test"
    echo "=========================================="
    echo ""

    check_prerequisites
    setup_test_env
    start_daemon

    # docker pull first to get the image
    log_info "Pulling alpine image..."
    if ! DOCKER_HOST="unix://$TEST_DIR/docker.sock" timeout 90 docker pull alpine:latest > "$TEST_DIR/pull.log" 2>&1; then
        log_error "docker pull failed"
        cat "$TEST_DIR/pull.log"
        print_summary
        exit 1
    fi
    log_info "docker pull: OK"

    # Start docker create in background - this triggers VM creation
    log_info "Creating container (triggers VM boot)..."
    DOCKER_HOST="unix://$TEST_DIR/docker.sock" docker create --label "$TEST_LABEL" alpine echo "test" \
        > "$TEST_DIR/container_id" 2> "$TEST_DIR/container_create.err" &
    CREATE_PID=$!

    # Wait for agent to connect
    if wait_for_agent; then
        RESULT_VM_BOOT="PASS"
        RESULT_VSOCK="PASS"
        RESULT_AGENT="PASS"

        # Wait for create to complete
        if wait $CREATE_PID; then
            local cid
            cid=$(cat "$TEST_DIR/container_id" 2>/dev/null)
            log_info "container create: OK (ID: ${cid:0:12})"
            RESULT_CONTAINER_CREATE="PASS"
        else
            log_warn "container create: FAILED"
            RESULT_CONTAINER_CREATE="FAIL"
        fi
    else
        RESULT_VM_BOOT="FAIL"
        RESULT_VSOCK="FAIL"
        RESULT_AGENT="FAIL"
        # Kill create if agent failed
        kill $CREATE_PID 2>/dev/null || true
        print_summary
        exit 1
    fi

    # --- Phase 1.2 / 1.4: Container lifecycle tests ---

    echo ""
    log_info "=== Container Lifecycle Tests (Phase 1.2 / 1.4) ==="
    echo ""

    # Test 1: docker run alpine echo hello
    if test_container_run; then
        RESULT_CONTAINER_RUN="PASS"
    else
        RESULT_CONTAINER_RUN="FAIL"
    fi

    # Test 2: background container + docker ps
    if test_background_container; then
        RESULT_BACKGROUND_CONTAINER="PASS"
    else
        RESULT_BACKGROUND_CONTAINER="FAIL"
    fi

    # Test 3: docker logs
    if test_docker_logs; then
        RESULT_DOCKER_LOGS="PASS"
    else
        RESULT_DOCKER_LOGS="FAIL"
    fi

    # Test 4: docker exec
    if test_docker_exec; then
        RESULT_DOCKER_EXEC="PASS"
    else
        RESULT_DOCKER_EXEC="FAIL"
    fi

    # Test 5: docker stop + docker rm
    if test_stop_rm; then
        RESULT_STOP_RM="PASS"
    else
        RESULT_STOP_RM="FAIL"
    fi

    print_summary
}

main "$@"
