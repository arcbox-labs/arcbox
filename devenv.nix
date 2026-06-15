{ pkgs, lib, ... }:

{
  # Host build deps. The C cross-compiler for the aarch64-musl guest agent
  # still comes from `brew install FiloSottile/musl-cross/musl-cross` —
  # pkgsCross on darwin is not cached and would force a multi-hour rebuild.
  packages = with pkgs; [
    protobuf
    pkg-config
    cargo-nextest
    cargo-watch
    cargo-about
  ] ++ lib.optionals pkgs.stdenv.isDarwin [
    pkgs.libiconv
    # arcbox-vmm links macOS 15+ Hypervisor GIC APIs (hv_gic_*). The nix darwin
    # stdenv defaults to the 14.4 SDK, whose Hypervisor.tbd lacks those symbols,
    # so `cargo build -p arcbox-daemon` fails to link locally. Pin a 15+ SDK to
    # match CI (system Xcode 26 SDK). The setup hook makes this the active
    # DEVELOPER_DIR/SDKROOT since it is the highest-versioned SDK in scope.
    pkgs.apple-sdk_26
  ];

  languages.rust = {
    enable = true;
    channel = "stable";
    targets = [
      "aarch64-unknown-linux-musl"
      "x86_64-unknown-linux-musl"
    ];
  };

  env.PROTOC = "${pkgs.protobuf}/bin/protoc";
}
