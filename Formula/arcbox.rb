# Homebrew formula for ArcBox
# High-performance container and virtual machine runtime for macOS.
#
# To install from a local tap during development:
#   brew install --formula ./Formula/arcbox.rb

class Arcbox < Formula
  desc "High-performance container and VM runtime for macOS"
  homepage "https://github.com/arcboxd/arcbox"
  version "0.0.1-alpha.1"
  license all_of: ["MIT", "Apache-2.0"]

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/arcboxd/arcbox/releases/download/v#{version}/arcbox-darwin-arm64-v#{version}.tar.gz"
      sha256 "PLACEHOLDER_ARM64_SHA256"
    elsif Hardware::CPU.intel?
      url "https://github.com/arcboxd/arcbox/releases/download/v#{version}/arcbox-darwin-x86_64-v#{version}.tar.gz"
      sha256 "PLACEHOLDER_X86_64_SHA256"
    end
  end

  depends_on :macos
  depends_on macos: :monterey  # Virtualization.framework requires macOS 12+

  def install
    bin.install "arcbox"

    # Write entitlements plist for codesigning.
    entitlements = buildpath / "entitlements.plist"
    entitlements.write <<~PLIST
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0">
      <dict>
          <key>com.apple.security.virtualization</key>
          <true/>
      </dict>
      </plist>
    PLIST

    # Codesign with virtualization entitlement.
    system "codesign", "--entitlements", entitlements,
                       "--force", "-s", "-",
                       bin / "arcbox"

    # Create data and log directories.
    (var / "arcbox").mkpath
    (var / "log" / "arcbox").mkpath
  end

  def post_install
    # Download boot assets (kernel + initramfs).
    system bin / "arcbox", "boot", "prefetch"
  end

  # launchd service for the ArcBox daemon.
  service do
    run [opt_bin / "arcbox", "daemon", "--foreground", "--docker-integration"]
    keep_alive successful_exit: false
    log_path var / "log" / "arcbox" / "daemon.stdout.log"
    error_log_path var / "log" / "arcbox" / "daemon.stderr.log"
    environment_variables PATH: std_service_path_env,
                          HOME: Dir.home
    process_type :background
  end

  def caveats
    <<~EOS
      ArcBox has been installed and signed with the Virtualization.framework entitlement.

      To start the ArcBox daemon as a background service:
        brew services start arcbox

      To use ArcBox as your Docker backend:
        arcbox docker use

      After enabling Docker integration, standard Docker CLI commands
      will be routed through ArcBox:
        docker run hello-world

      Data directory: ~/.arcbox
      Logs: #{var}/log/arcbox/
    EOS
  end

  test do
    assert_match "ArcBox version", shell_output("#{bin}/arcbox version")
  end
end
