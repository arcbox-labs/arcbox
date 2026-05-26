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
