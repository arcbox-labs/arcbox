#!/bin/bash
# Boot assets integration test script
# Tests kernel boot, vsock connectivity, and agent functionality

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TEST_DIR="/tmp/arcbox-boot-test-$$"
BOOT_ASSETS_VERSION="0.0.1-alpha.2"

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
    pkill -f "arcbox.*daemon.*$TEST_DIR" 2>/dev/null || true
    if [[ -n "${KEEP_TEST_DIR:-}" ]]; then
        log_warn "KEEP_TEST_DIR set, preserving: $TEST_DIR"
    else
        rm -rf "$TEST_DIR"
    fi
}

trap cleanup EXIT

# Check for required files
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check for arcbox binary
    if [[ ! -f "$PROJECT_DIR/target/release/arcbox" ]]; then
        log_error "arcbox binary not found. Run: cargo build --release"
        exit 1
    fi

    # Check for entitlements
    if ! codesign -d --entitlements :- "$PROJECT_DIR/target/release/arcbox" 2>/dev/null | grep -q "com.apple.security.virtualization"; then
        log_warn "Binary not signed with virtualization entitlement. Signing..."
        codesign --entitlements "$PROJECT_DIR/tests/resources/entitlements.plist" --force -s - "$PROJECT_DIR/target/release/arcbox"
    fi

    log_info "Prerequisites OK"
}

# Setup test environment with boot assets
setup_test_env() {
    log_info "Setting up test environment: $TEST_DIR"

    mkdir -p "$TEST_DIR/boot/$BOOT_ASSETS_VERSION"

    # Use development boot assets
    local dev_boot_dir="$PROJECT_DIR/boot-assets/dev"

    if [[ -f "$dev_boot_dir/kernel" ]] && [[ -f "$dev_boot_dir/initramfs.cpio.gz" ]]; then
        cp "$dev_boot_dir/kernel" "$TEST_DIR/boot/$BOOT_ASSETS_VERSION/"
        cp "$dev_boot_dir/initramfs.cpio.gz" "$TEST_DIR/boot/$BOOT_ASSETS_VERSION/"
        log_info "Using development boot assets from $dev_boot_dir"
    else
        log_error "Development boot assets not found at $dev_boot_dir"
        log_error "Run: ./scripts/setup-dev-boot-assets.sh"
        exit 1
    fi
}

# Start daemon
start_daemon() {
    log_info "Starting daemon..."

    "$PROJECT_DIR/target/release/arcbox" daemon \
        --data-dir "$TEST_DIR" \
        --socket "$TEST_DIR/docker.sock" \
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
    echo ""

    if grep -q "Agent is ready" "$TEST_DIR/daemon.log" 2>/dev/null; then
        echo -e "VM Boot:        ${GREEN}PASS${NC}"
        echo -e "vsock:          ${GREEN}PASS${NC}"
        echo -e "Agent:          ${GREEN}PASS${NC}"
    else
        echo -e "VM Boot:        ${RED}FAIL${NC}"
    fi

    if grep -q "Created container" "$TEST_DIR/daemon.log" 2>/dev/null; then
        echo -e "Container:      ${GREEN}PASS${NC}"
    else
        echo -e "Container:      ${YELLOW}SKIP${NC}"
    fi

    echo ""
    echo "Log: $TEST_DIR/daemon.log"
    echo "=========================================="
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
    DOCKER_HOST="unix://$TEST_DIR/docker.sock" docker create alpine echo "test" \
        > "$TEST_DIR/container_id" 2>&1 &
    CREATE_PID=$!

    # Wait for agent to connect
    if wait_for_agent; then
        # Wait for create to complete
        if wait $CREATE_PID; then
            local cid
            cid=$(cat "$TEST_DIR/container_id" 2>/dev/null)
            log_info "container create: OK (ID: ${cid:0:12})"
        else
            log_warn "container create: FAILED"
        fi
    else
        # Kill create if agent failed
        kill $CREATE_PID 2>/dev/null || true
    fi

    print_summary
}

main "$@"
