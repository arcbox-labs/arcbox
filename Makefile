# ArcBox Development Makefile

PROFILE ?= debug
# Local dev signing uses the dev entitlements (disables library validation
# for nix-store libiconv). The release path (.github/workflows/release.yml)
# signs with bundle/arcbox.entitlements, which keeps validation enabled.
ENTITLEMENTS := bundle/arcbox.dev.entitlements
AGENT_TARGET := aarch64-unknown-linux-musl

# Signing identity: auto-detect "Developer ID Application: ArcBox, Inc."
# from keychain. Override with: make sign SIGN_IDENTITY="..."
# Use SIGN_IDENTITY=- for ad-hoc signing (won't work with Virtualization.framework
# on recent macOS).
SIGN_IDENTITY ?= $(shell security find-identity -v -p codesigning 2>/dev/null \
	| grep -o '"Developer ID Application: ArcBox, Inc\.[^"]*"' \
	| head -1 | tr -d '"')

BINARIES := arcbox-daemon arcbox-helper abctl

ifeq ($(PROFILE),release)
  CARGO_FLAGS := --release
  TARGET_DIR := target/release
else
  CARGO_FLAGS :=
  TARGET_DIR := target/debug
endif

.PHONY: build build-release build-cli build-daemon build-helper build-agent \
        build-fleet-agent fleet-proto-sync \
        test check fmt clean \
        setup-boot-assets sign sign-daemon sign-all verify run-daemon \
        run-helper install-helper reload-helper test-helper

## ── Build ──────────────────────────────────────────────

build:
	cargo build $(CARGO_FLAGS)

build-release:
	$(MAKE) build PROFILE=release

build-cli:
	cargo build -p arcbox-cli $(CARGO_FLAGS)

build-daemon:
	cargo build -p arcbox-daemon $(CARGO_FLAGS)

build-helper:
	cargo build -p arcbox-helper $(CARGO_FLAGS)

build-agent:
	cargo build -p arcbox-agent --target $(AGENT_TARGET) --release
	cargo build -p arcbox-vm --bin vm-agent --target $(AGENT_TARGET) --release

build-fleet-agent:
	cargo build -p arcbox-fleet-agent $(CARGO_FLAGS)

# Refresh the vendored Fleet proto from the published BSR module.
fleet-proto-sync:
	buf export buf.build/arcboxlabs/fleet -o fleet/arcbox-fleet-proto/proto

## ── Quality ────────────────────────────────────────────

check:
	cargo clippy --workspace --all-targets -- -D warnings
	cargo fmt --check

fmt:
	cargo fmt

test:
	cargo test --workspace

## ── Code Signing ─────────────────────────────────────

sign-daemon: build-daemon
	@if [ -z "$(SIGN_IDENTITY)" ]; then \
		echo "ERROR: No Developer ID signing identity found." >&2; \
		echo "  Install the ArcBox Developer ID certificate or set SIGN_IDENTITY:" >&2; \
		echo "  make sign-daemon SIGN_IDENTITY=\"Developer ID Application: ...\"" >&2; \
		exit 1; \
	fi
	codesign --force --options runtime \
		--identifier com.arcboxlabs.desktop.daemon \
		--entitlements $(ENTITLEMENTS) \
		--sign "$(SIGN_IDENTITY)" \
		$(TARGET_DIR)/arcbox-daemon
	@codesign -v --deep --strict $(TARGET_DIR)/arcbox-daemon && echo "✓ arcbox-daemon signed"

sign-all: build
	@if [ -z "$(SIGN_IDENTITY)" ]; then \
		echo "ERROR: No Developer ID signing identity found." >&2; \
		exit 1; \
	fi
	codesign --force --options runtime \
		--identifier com.arcboxlabs.desktop.daemon \
		--entitlements $(ENTITLEMENTS) \
		--sign "$(SIGN_IDENTITY)" \
		$(TARGET_DIR)/arcbox-daemon
	codesign --force --options runtime \
		--identifier com.arcboxlabs.desktop.helper \
		--sign "$(SIGN_IDENTITY)" \
		$(TARGET_DIR)/arcbox-helper
	codesign --force --options runtime \
		--identifier com.arcboxlabs.desktop.cli \
		--sign "$(SIGN_IDENTITY)" \
		$(TARGET_DIR)/abctl
	@for bin in $(BINARIES); do \
		codesign -v --deep --strict $(TARGET_DIR)/$$bin && echo "✓ $$bin signed"; \
	done

# Legacy ad-hoc sign (kept for CI smoke tests where no Developer ID exists).
sign:
	codesign --force --options runtime \
		--entitlements $(ENTITLEMENTS) \
		-s - $(TARGET_DIR)/arcbox-daemon

verify:
	@for bin in $(BINARIES); do \
		if [ -f $(TARGET_DIR)/$$bin ]; then \
			echo "--- $$bin ---"; \
			codesign -d -v --entitlements :- $(TARGET_DIR)/$$bin 2>&1 | head -5; \
			echo; \
		fi; \
	done

## ── Dev Workflow ───────────────────────────────────────

setup-boot-assets:
	cargo xtask dev boot-assets

run-daemon:
	cargo xtask macos dev --sign false

# Run the helper in manual mode (no launchd). Uses /tmp socket by default
# so the daemon can connect without launchd registration.
# Usage:
#   make run-helper                    # default socket /tmp/arcbox-helper.sock
#   make run-helper HELPER_SOCKET=/var/run/arcbox-helper.sock
HELPER_SOCKET ?= /tmp/arcbox-helper.sock
run-helper: build-helper
	sudo ARCBOX_HELPER_SOCKET=$(HELPER_SOCKET) $(TARGET_DIR)/arcbox-helper

# Install the helper into launchd (production-like). Requires sudo.
install-helper: build-helper
	sudo install -o root -g wheel -m 755 $(TARGET_DIR)/arcbox-helper /usr/local/libexec/arcbox-helper
	sudo cp bundle/com.arcboxlabs.desktop.helper.plist /Library/LaunchDaemons/
	-sudo launchctl bootout system/com.arcboxlabs.desktop.helper 2>/dev/null
	sudo launchctl bootstrap system /Library/LaunchDaemons/com.arcboxlabs.desktop.helper.plist
	@echo "✓ arcbox-helper installed and registered with launchd"

# Rebuild and hot-reload the helper in launchd (bootout → copy → bootstrap).
reload-helper: build-helper
	-sudo launchctl bootout system/com.arcboxlabs.desktop.helper 2>/dev/null
	sudo cp $(TARGET_DIR)/arcbox-helper /usr/local/libexec/arcbox-helper
	sudo launchctl bootstrap system /Library/LaunchDaemons/com.arcboxlabs.desktop.helper.plist
	@echo "✓ arcbox-helper reloaded"

# Full helper regression suite (no root): unit + mock tarpc + real-binary E2E.
# E2E uses ARCBOX_HELPER_TEST_ROOT sandbox (debug builds only).
test-helper:
	cargo test -p arcbox-constants --features std --lib helper::
	cargo test -p arcbox-constants --features std --lib is_arcbox_owned
	cargo test -p arcbox-helper --lib
	cargo test -p arcbox-helper --bins
	cargo test -p arcbox-helper --tests
	cargo clippy -p arcbox-helper -- -D warnings

## ── Cleanup ───────────────────────────────────────────

clean:
	cargo clean
