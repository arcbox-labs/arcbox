#!/bin/bash
#
# Run E2E integration tests for ArcBox
#
# Usage:
#   ./tests/integration/run_e2e.sh           # Run all E2E tests
#   ./tests/integration/run_e2e.sh vm        # Run only VM lifecycle tests
#   ./tests/integration/run_e2e.sh image     # Run only image ops tests
#   ./tests/integration/run_e2e.sh container # Run only container lifecycle tests
#   ./tests/integration/run_e2e.sh workflow  # Run only full workflow tests

set -e

# Navigate to project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if arcbox binary exists
    if [[ ! -f "$PROJECT_ROOT/target/debug/arcbox" ]]; then
        log_warn "arcbox binary not found, building..."
        cargo build -p arcbox-cli
    fi

    # Check for test resources
    RESOURCES_DIR="$PROJECT_ROOT/tests/resources"

    if [[ ! -f "$RESOURCES_DIR/Image-arm64" ]]; then
        log_warn "Kernel not found. Run: ./tests/resources/download-kernel.sh"
        MISSING_RESOURCES=1
    fi

    if [[ ! -f "$RESOURCES_DIR/initramfs-arcbox" ]]; then
        log_warn "Initramfs not found. Run: ./tests/resources/build-initramfs.sh"
        MISSING_RESOURCES=1
    fi

    if [[ -n "$MISSING_RESOURCES" ]]; then
        log_error "Some resources are missing. E2E tests may be skipped."
        log_info "To download/build missing resources:"
        echo "  cd $RESOURCES_DIR"
        echo "  ./download-kernel.sh"
        echo "  ./build-initramfs.sh"
    else
        log_info "All prerequisites satisfied"
    fi
}

# Build test harness
build_tests() {
    log_info "Building E2E test harness..."
    cargo build -p arcbox-e2e
}

# Run specific test suite
run_tests() {
    local suite="$1"
    local extra_args="${@:2}"

    log_info "Running E2E tests: $suite"

    # Set environment variables
    export RUST_LOG=${RUST_LOG:-info}
    export RUST_BACKTRACE=${RUST_BACKTRACE:-1}
    export ARCBOX_TEST_TIMEOUT=${ARCBOX_TEST_TIMEOUT:-300}

    case "$suite" in
        vm|vm_lifecycle)
            cargo test -p arcbox-e2e --test vm_lifecycle -- --ignored $extra_args
            ;;
        image|image_ops)
            cargo test -p arcbox-e2e --test image_ops -- --ignored $extra_args
            ;;
        container|container_lifecycle)
            cargo test -p arcbox-e2e --test container_lifecycle -- --ignored $extra_args
            ;;
        workflow|full_workflow)
            cargo test -p arcbox-e2e --test full_workflow -- --ignored $extra_args
            ;;
        all|"")
            log_info "Running all E2E test suites..."
            cargo test -p arcbox-e2e -- --ignored $extra_args
            ;;
        quick)
            # Run a quick smoke test
            log_info "Running quick smoke test..."
            cargo test -p arcbox-e2e --test vm_lifecycle test_machine_create -- --ignored $extra_args
            ;;
        *)
            log_error "Unknown test suite: $suite"
            echo "Available suites: vm, image, container, workflow, all, quick"
            exit 1
            ;;
    esac
}

# Print test results summary
print_summary() {
    log_info "Test run completed"
}

# Main
main() {
    local suite="${1:-all}"
    local extra_args="${@:2}"

    echo "========================================"
    echo " ArcBox E2E Integration Tests"
    echo "========================================"
    echo

    check_prerequisites
    echo

    build_tests
    echo

    run_tests "$suite" $extra_args
    echo

    print_summary
}

# Handle arguments
case "$1" in
    -h|--help)
        echo "Usage: $0 [suite] [extra-args]"
        echo
        echo "Available test suites:"
        echo "  all        Run all E2E tests (default)"
        echo "  vm         Run VM lifecycle tests"
        echo "  image      Run image operation tests"
        echo "  container  Run container lifecycle tests"
        echo "  workflow   Run full workflow tests"
        echo "  quick      Run quick smoke test"
        echo
        echo "Extra arguments are passed to cargo test"
        echo
        echo "Environment variables:"
        echo "  RUST_LOG              Log level (default: info)"
        echo "  RUST_BACKTRACE        Enable backtraces (default: 1)"
        echo "  ARCBOX_TEST_TIMEOUT   Test timeout in seconds (default: 300)"
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
