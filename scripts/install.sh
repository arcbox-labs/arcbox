#!/bin/bash
# ArcBox installer for macOS
# Usage: curl -fsSL https://get.arcbox.dev | bash
#
# Environment variables:
#   ARCBOX_VERSION    - Specific version to install (default: latest)
#   ARCBOX_INSTALL_DIR - Installation directory (default: /usr/local/bin)
#   ARCBOX_NO_PREFETCH - Skip boot asset prefetch if set to 1
#   ARCBOX_NO_DAEMON   - Skip launchd agent installation if set to 1

set -euo pipefail

# --- Constants ---

GITHUB_REPO="arcboxd/arcbox"
INSTALL_DIR="${ARCBOX_INSTALL_DIR:-/usr/local/bin}"
DATA_DIR="$HOME/.arcbox"
LOG_DIR="$HOME/Library/Logs/arcbox"
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
PLIST_LABEL="dev.arcbox.daemon"
PLIST_FILE="$LAUNCH_AGENTS_DIR/$PLIST_LABEL.plist"

# --- Colors ---

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# --- Helpers ---

info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
bold()  { echo -e "${BOLD}$1${NC}"; }

# Print a fatal error and exit.
die() {
    error "$1"
    exit 1
}

# Check if a command exists.
has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# --- Pre-flight checks ---

preflight() {
    # macOS only
    if [[ "$(uname -s)" != "Darwin" ]]; then
        die "ArcBox currently only supports macOS. Linux support is planned."
    fi

    # Detect architecture
    ARCH="$(uname -m)"
    case "$ARCH" in
        arm64|aarch64)
            ARCH="arm64"
            ;;
        x86_64)
            ARCH="x86_64"
            ;;
        *)
            die "Unsupported architecture: $ARCH"
            ;;
    esac

    # Require curl
    if ! has_cmd curl; then
        die "curl is required but not found. Install Xcode Command Line Tools: xcode-select --install"
    fi

    # Require codesign (ships with Xcode CLT)
    if ! has_cmd codesign; then
        die "codesign is required but not found. Install Xcode Command Line Tools: xcode-select --install"
    fi

    # Check macOS version (Virtualization.framework requires macOS 12+)
    MACOS_VERSION="$(sw_vers -productVersion)"
    MACOS_MAJOR="$(echo "$MACOS_VERSION" | cut -d. -f1)"
    if [[ "$MACOS_MAJOR" -lt 12 ]]; then
        die "ArcBox requires macOS 12 (Monterey) or later. Current: $MACOS_VERSION"
    fi

    info "Platform: macOS $MACOS_VERSION ($ARCH)"
}

# --- Version resolution ---

resolve_version() {
    if [[ -n "${ARCBOX_VERSION:-}" ]]; then
        VERSION="$ARCBOX_VERSION"
        info "Using specified version: $VERSION"
        return
    fi

    info "Resolving latest version..."
    # Fetch latest release tag from GitHub API
    local api_url="https://api.github.com/repos/$GITHUB_REPO/releases/latest"
    local response
    response="$(curl -fsSL --retry 3 "$api_url" 2>/dev/null)" || die "Failed to fetch latest release from GitHub. Check your network connection."

    VERSION="$(echo "$response" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/')"

    if [[ -z "$VERSION" ]]; then
        die "Failed to parse latest version from GitHub API response."
    fi

    info "Latest version: $VERSION"
}

# --- Download and install ---

download_and_install() {
    local url="https://github.com/$GITHUB_REPO/releases/download/v${VERSION}/arcbox-darwin-${ARCH}-v${VERSION}.tar.gz"
    local tmpdir
    tmpdir="$(mktemp -d)" || die "Failed to create temporary directory."

    # Ensure cleanup on exit.
    trap 'rm -rf "$tmpdir"' EXIT

    info "Downloading ArcBox v${VERSION} for darwin/${ARCH}..."
    local tarball="$tmpdir/arcbox.tar.gz"
    curl -fSL --retry 3 --progress-bar -o "$tarball" "$url" || die "Download failed. URL: $url"

    info "Extracting..."
    tar xzf "$tarball" -C "$tmpdir" || die "Failed to extract archive."

    # Locate binaries (may be at top level or inside a directory)
    local arcbox_binary=""
    local daemon_binary=""
    if [[ -f "$tmpdir/arcbox" ]]; then
        arcbox_binary="$tmpdir/arcbox"
    else
        arcbox_binary="$(find "$tmpdir" -name arcbox -type f | head -1)"
    fi
    if [[ -f "$tmpdir/arcbox-daemon" ]]; then
        daemon_binary="$tmpdir/arcbox-daemon"
    else
        daemon_binary="$(find "$tmpdir" -name arcbox-daemon -type f | head -1)"
    fi

    if [[ -z "$arcbox_binary" || ! -f "$arcbox_binary" ]]; then
        die "Could not find arcbox binary in archive."
    fi
    if [[ -z "$daemon_binary" || ! -f "$daemon_binary" ]]; then
        die "Could not find arcbox-daemon binary in archive."
    fi

    # Codesign with virtualization entitlement
    info "Signing binary with Virtualization.framework entitlement..."
    local entitlements="$tmpdir/entitlements.plist"
    cat > "$entitlements" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.virtualization</key>
    <true/>
</dict>
</plist>
PLIST
    codesign --entitlements "$entitlements" --force -s - "$arcbox_binary" 2>/dev/null || warn "Codesign failed for arcbox. VM features may not work without the virtualization entitlement."
    codesign --entitlements "$entitlements" --force -s - "$daemon_binary" 2>/dev/null || warn "Codesign failed for arcbox-daemon. VM features may not work without the virtualization entitlement."

    # Install binaries
    info "Installing to ${INSTALL_DIR}/arcbox and ${INSTALL_DIR}/arcbox-daemon..."
    if [[ -w "$INSTALL_DIR" ]]; then
        install -m 755 "$arcbox_binary" "$INSTALL_DIR/arcbox"
        install -m 755 "$daemon_binary" "$INSTALL_DIR/arcbox-daemon"
    else
        warn "Write permission denied for $INSTALL_DIR. Using sudo..."
        sudo install -m 755 "$arcbox_binary" "$INSTALL_DIR/arcbox"
        sudo install -m 755 "$daemon_binary" "$INSTALL_DIR/arcbox-daemon"
    fi

    # Verify installation
    if ! "$INSTALL_DIR/arcbox" version >/dev/null 2>&1; then
        warn "Installed binary does not respond to 'version'. It may require additional setup."
    fi
    if ! "$INSTALL_DIR/arcbox-daemon" --help >/dev/null 2>&1; then
        warn "Installed daemon binary does not respond to '--help'. It may require additional setup."
    fi
}

# --- Directory setup ---

setup_directories() {
    info "Creating directory structure..."
    mkdir -p "$DATA_DIR"
    mkdir -p "$LOG_DIR"
}

# --- launchd agent ---

install_launchd_agent() {
    if [[ "${ARCBOX_NO_DAEMON:-0}" == "1" ]]; then
        info "Skipping launchd agent installation (ARCBOX_NO_DAEMON=1)."
        return
    fi

    info "Installing launchd agent..."
    mkdir -p "$LAUNCH_AGENTS_DIR"

    # Unload existing agent if present.
    if launchctl list "$PLIST_LABEL" >/dev/null 2>&1; then
        launchctl bootout "gui/$(id -u)/$PLIST_LABEL" 2>/dev/null || true
    fi

    cat > "$PLIST_FILE" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_LABEL}</string>

    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/arcbox-daemon</string>
        <string>--docker-integration</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>StandardOutPath</key>
    <string>${LOG_DIR}/daemon.stdout.log</string>

    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/daemon.stderr.log</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>HOME</key>
        <string>${HOME}</string>
    </dict>

    <key>ProcessType</key>
    <string>Background</string>

    <key>ThrottleInterval</key>
    <integer>5</integer>
</dict>
</plist>
PLIST

    # Load the agent
    launchctl bootstrap "gui/$(id -u)" "$PLIST_FILE" 2>/dev/null || launchctl load "$PLIST_FILE" 2>/dev/null || warn "Failed to load launchd agent. You can start it manually: launchctl load $PLIST_FILE"

    info "Daemon will start automatically on login."
}

# --- Boot asset prefetch ---

prefetch_boot_assets() {
    if [[ "${ARCBOX_NO_PREFETCH:-0}" == "1" ]]; then
        info "Skipping boot asset prefetch (ARCBOX_NO_PREFETCH=1)."
        return
    fi

    info "Downloading boot assets (kernel + initramfs)..."
    "$INSTALL_DIR/arcbox" boot prefetch || warn "Boot asset prefetch failed. You can retry later: arcbox boot prefetch"
}

# --- Summary ---

print_summary() {
    echo ""
    bold "============================================"
    bold "  ArcBox v${VERSION} installed successfully!"
    bold "============================================"
    echo ""
    echo "  Binaries:  ${INSTALL_DIR}/arcbox, ${INSTALL_DIR}/arcbox-daemon"
    echo "  Data dir:  ${DATA_DIR}"
    echo "  Logs:      ${LOG_DIR}"
    if [[ "${ARCBOX_NO_DAEMON:-0}" != "1" ]]; then
        echo "  Daemon:    launchd agent (${PLIST_LABEL})"
    fi
    echo ""
    bold "Quick start:"
    echo "  arcbox daemon                    # Start daemon in background"
    echo "  arcbox docker enable             # Use ArcBox with Docker CLI"
    echo "  docker run hello-world           # Run via Docker CLI"
    echo "  arcbox machine list              # List VMs"
    echo ""
    bold "Docker integration:"
    echo "  arcbox docker enable             # Use ArcBox as Docker backend"
    echo "  docker run hello-world           # Works with standard Docker CLI"
    echo ""
    bold "Manage the daemon:"
    echo "  arcbox daemon                    # Start in background"
    echo "  arcbox daemon stop               # Stop daemon"
    echo "  launchctl kickstart -k gui/$(id -u)/${PLIST_LABEL}  # Restart"
    echo "  launchctl bootout gui/$(id -u)/${PLIST_LABEL}       # Stop"
    echo ""

    # Check if INSTALL_DIR is in PATH
    if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
        warn "${INSTALL_DIR} is not in your PATH."
        echo "  Add it to your shell profile:"
        echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
        echo ""
    fi
}

# --- Uninstall hint ---

print_uninstall_hint() {
    echo "To uninstall ArcBox:"
    echo "  launchctl bootout gui/$(id -u)/${PLIST_LABEL} 2>/dev/null"
    echo "  rm -f ${INSTALL_DIR}/arcbox ${INSTALL_DIR}/arcbox-daemon"
    echo "  rm -f ${PLIST_FILE}"
    echo "  rm -rf ${DATA_DIR}"
    echo "  rm -rf ${LOG_DIR}"
    echo ""
}

# --- Main ---

main() {
    bold "ArcBox Installer"
    echo ""

    preflight
    resolve_version
    download_and_install
    setup_directories
    install_launchd_agent
    prefetch_boot_assets
    print_summary
}

main "$@"
