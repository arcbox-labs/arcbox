#!/bin/bash
# Docker CLI E2E Test Runner for ArcBox
#
# This script runs Docker CLI's official e2e tests against arcbox-docker.
#
# Usage:
#   ./scripts/docker-cli-e2e.sh [options]
#
# Options:
#   --build-only    Only build the e2e test image, don't run tests
#   --skip-build    Skip building the e2e test image
#   --test-pattern  Run only tests matching this pattern (e.g., "TestVersion")
#
# Prerequisites:
#   - Docker installed (for building e2e test image)
#   - arcbox binary built (cargo build)
#   - kernel/initramfs prepared (tests/resources/download-kernel.sh)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DOCKER_CLI_PATH="${DOCKER_CLI_PATH:-/Users/Shiro/Developer/arcboxd/docker-cli}"
ARCBOX_BINARY="${PROJECT_ROOT}/target/debug/arcbox"

# Test configuration
TEST_SOCKET="/tmp/arcbox-e2e-test.sock"
TEST_DATA_DIR="/tmp/arcbox-e2e-data"
E2E_IMAGE_NAME="docker-cli-e2e-arcbox"

# Options
BUILD_ONLY=false
SKIP_BUILD=false
TEST_PATTERN=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --build-only)
            BUILD_ONLY=true
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --test-pattern)
            TEST_PATTERN="$2"
            shift 2
            ;;
        *)
            TEST_PATTERN="$1"
            shift
            ;;
    esac
done

# Cleanup function
cleanup() {
    echo -e "${BLUE}Cleaning up...${NC}"

    # Kill daemon if running
    if [[ -n "${DAEMON_PID:-}" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi

    # Remove socket and data dir
    rm -f "$TEST_SOCKET"
    rm -rf "$TEST_DATA_DIR"

    echo -e "${GREEN}Cleanup complete${NC}"
}

# Print header
print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  ArcBox Docker CLI E2E Test Runner${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"

    # Check Docker (needed to build e2e image)
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Error: Docker is not installed (needed to build e2e test image)${NC}"
        exit 1
    fi
    echo "  ✓ Docker $(docker --version | awk '{print $3}' | tr -d ',')"

    # Check arcbox binary
    if [[ ! -x "$ARCBOX_BINARY" ]]; then
        echo -e "${RED}Error: arcbox binary not found at $ARCBOX_BINARY${NC}"
        echo "  Run: cargo build"
        exit 1
    fi
    echo "  ✓ arcbox binary"

    # Check docker-cli repo
    if [[ ! -d "$DOCKER_CLI_PATH" ]]; then
        echo -e "${RED}Error: docker-cli repo not found at $DOCKER_CLI_PATH${NC}"
        echo "  Set DOCKER_CLI_PATH environment variable"
        exit 1
    fi
    echo "  ✓ docker-cli repo"

    # Check kernel/initramfs
    KERNEL_PATH="${PROJECT_ROOT}/tests/resources/Image-arm64"
    INITRAMFS_PATH="${PROJECT_ROOT}/tests/resources/initramfs-arcbox"

    if [[ -f "$KERNEL_PATH" ]] && [[ -f "$INITRAMFS_PATH" ]]; then
        echo "  ✓ kernel and initramfs"
        HAS_VM_SUPPORT=true
    else
        echo -e "  ${YELLOW}⚠ kernel/initramfs not found (VM tests will be limited)${NC}"
        HAS_VM_SUPPORT=false
    fi

    echo ""
}

# Build e2e test image
build_e2e_image() {
    if [[ "$SKIP_BUILD" == "true" ]]; then
        echo -e "${YELLOW}Skipping e2e image build (--skip-build)${NC}"
        return 0
    fi

    echo -e "${YELLOW}Building e2e test image...${NC}"
    cd "$DOCKER_CLI_PATH"

    # Build using docker buildx bake
    IMAGE_NAME="$E2E_IMAGE_NAME" docker buildx bake e2e-image

    echo -e "${GREEN}✓ E2E image built: $E2E_IMAGE_NAME${NC}"
    echo ""
}

# Start arcbox daemon
start_daemon() {
    echo -e "${YELLOW}Starting arcbox daemon...${NC}"

    # Create data directory
    mkdir -p "$TEST_DATA_DIR"

    # Build daemon command
    DAEMON_CMD="$ARCBOX_BINARY daemon start --socket $TEST_SOCKET --data-dir $TEST_DATA_DIR"

    if [[ "$HAS_VM_SUPPORT" == "true" ]]; then
        DAEMON_CMD="$DAEMON_CMD --kernel $KERNEL_PATH --initramfs $INITRAMFS_PATH"
    fi

    # Start daemon in background
    RUST_LOG=info $DAEMON_CMD &
    DAEMON_PID=$!

    # Wait for socket to appear
    echo -n "  Waiting for daemon"
    for i in {1..30}; do
        if [[ -S "$TEST_SOCKET" ]]; then
            echo ""
            echo -e "  ${GREEN}✓ Daemon started (PID: $DAEMON_PID)${NC}"
            return 0
        fi
        echo -n "."
        sleep 0.5
    done

    echo ""
    echo -e "${RED}Error: Daemon failed to start${NC}"
    exit 1
}

# Test basic API connectivity
test_basic_api() {
    echo -e "${YELLOW}Testing basic API connectivity...${NC}"

    # Test /_ping
    echo -n "  /_ping: "
    if curl -s --unix-socket "$TEST_SOCKET" http://localhost/_ping | grep -q "OK"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        return 1
    fi

    # Test /version
    echo -n "  /version: "
    if curl -s --unix-socket "$TEST_SOCKET" http://localhost/version | grep -q "ApiVersion"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        return 1
    fi

    # Test /info
    echo -n "  /info: "
    if curl -s --unix-socket "$TEST_SOCKET" http://localhost/info | grep -q "ServerVersion"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        return 1
    fi

    # Test /containers/json
    echo -n "  /containers/json: "
    if curl -s --unix-socket "$TEST_SOCKET" "http://localhost/v1.43/containers/json" | grep -q "\["; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        return 1
    fi

    # Test /images/json
    echo -n "  /images/json: "
    if curl -s --unix-socket "$TEST_SOCKET" "http://localhost/v1.43/images/json" | grep -q "\["; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        return 1
    fi

    # Test /networks
    echo -n "  /networks: "
    if curl -s --unix-socket "$TEST_SOCKET" "http://localhost/v1.43/networks" | grep -q "bridge"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        return 1
    fi

    # Test /volumes
    echo -n "  /volumes: "
    if curl -s --unix-socket "$TEST_SOCKET" "http://localhost/v1.43/volumes" | grep -q "Volumes"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        return 1
    fi

    echo ""
    echo -e "${GREEN}Basic API tests passed!${NC}"
    echo ""
}

# Run Docker CLI e2e tests in container
run_e2e_tests() {
    echo -e "${YELLOW}Running Docker CLI e2e tests...${NC}"
    echo ""

    # Test flags
    TESTFLAGS=""
    if [[ -n "$TEST_PATTERN" ]]; then
        TESTFLAGS="-run $TEST_PATTERN"
        echo "  Test pattern: $TEST_PATTERN"
    fi

    # Skip tests that require features not yet implemented
    # - plugin tests (no plugin support yet)
    # - registry tests (need local registry:5000)
    # - stack/swarm tests (no swarm support)
    SKIP_TESTS="TestPlugin|TestStack|TestSwarm|TestRegistry|TestPush"
    if [[ -z "$TESTFLAGS" ]]; then
        TESTFLAGS="-skip '$SKIP_TESTS'"
    fi

    echo "  Mounting arcbox socket into container..."
    echo ""

    # Run e2e tests in container with arcbox socket mounted
    # REMOTE_DAEMON=1 tells the test to use external daemon
    # TEST_DOCKER_HOST points to our arcbox socket
    docker run --rm \
        -v "$TEST_SOCKET:/var/run/docker.sock" \
        -e REMOTE_DAEMON=1 \
        -e TEST_DOCKER_HOST="unix:///var/run/docker.sock" \
        -e TESTFLAGS="$TESTFLAGS" \
        -e TESTDIRS="./e2e/system/... ./e2e/global/... ./e2e/container/... ./e2e/image/..." \
        -e SKIP_PLUGIN_TESTS=1 \
        "$E2E_IMAGE_NAME" \
        ./scripts/test/e2e/run test "unix:///var/run/docker.sock" \
        2>&1 | tee /tmp/arcbox-e2e-full.log

    echo ""
}

# Summarize results
summarize_results() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Test Summary${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""

    if [[ -f /tmp/arcbox-e2e-full.log ]]; then
        passed=$(grep -c "^--- PASS:" /tmp/arcbox-e2e-full.log 2>/dev/null) || passed=0
        failed=$(grep -c "^--- FAIL:" /tmp/arcbox-e2e-full.log 2>/dev/null) || failed=0
        skipped=$(grep -c "^--- SKIP:" /tmp/arcbox-e2e-full.log 2>/dev/null) || skipped=0

        if [[ "$failed" -gt 0 ]]; then
            echo -e "  Result: ${RED}FAILED${NC}"
        else
            echo -e "  Result: ${GREEN}PASSED${NC}"
        fi

        echo "  Passed:  $passed"
        echo "  Failed:  $failed"
        echo "  Skipped: $skipped"

        if [[ "$failed" -gt 0 ]]; then
            echo ""
            echo -e "${YELLOW}Failed tests:${NC}"
            grep "^--- FAIL:" /tmp/arcbox-e2e-full.log | head -20
        fi
    else
        echo "  No test results found"
    fi

    echo ""
    echo "  Full log: /tmp/arcbox-e2e-full.log"
    echo ""
}

# Main
main() {
    print_header
    check_prerequisites

    # Build e2e image first (uses regular Docker)
    build_e2e_image

    if [[ "$BUILD_ONLY" == "true" ]]; then
        echo -e "${GREEN}Build complete. Use --skip-build to run tests.${NC}"
        exit 0
    fi

    # Set trap for cleanup
    trap cleanup EXIT

    # Start arcbox daemon
    start_daemon

    # Test basic API
    test_basic_api

    # Run e2e tests
    run_e2e_tests

    # Summarize results
    summarize_results
}

main "$@"
