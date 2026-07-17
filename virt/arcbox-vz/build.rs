//! Builds the ArcBoxVZShim Swift static library and links it (plus the Swift
//! runtime stubs and Virtualization.framework) into this crate.
//!
//! Non-macOS targets get no shim: the crate root is `#![cfg(target_os =
//! "macos")]`, so the library is empty there and this script must not touch
//! the Swift toolchain (docs.rs / Linux workspace builds).

use std::env;
use std::path::PathBuf;
use std::process::Command;

/// The system `xcrun`, isolated from nix/devenv toolchain overrides.
///
/// The devenv shell pins `SDKROOT`/`DEVELOPER_DIR` to a nix-store Apple SDK
/// for the C/Rust side (arcbox-vmm's hv_gic_* linking) and shadows `xcrun`
/// on PATH with xcbuild's fake. SwiftPM refuses an SDK whose Swift stdlib
/// was built by a different compiler than the active toolchain, so Swift
/// invocations must go through the real `/usr/bin/xcrun` and resolve the
/// SDK from the toolchain's own defaults.
fn xcrun() -> Command {
    let mut cmd = Command::new("/usr/bin/xcrun");
    cmd.env_remove("SDKROOT").env_remove("DEVELOPER_DIR");
    cmd
}

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    println!("cargo:rerun-if-changed=shim/Package.swift");
    println!("cargo:rerun-if-changed=shim/Sources");

    let have_swiftc = xcrun()
        .args(["--find", "swiftc"])
        .output()
        .is_ok_and(|o| o.status.success());
    assert!(
        have_swiftc,
        "arcbox-vz: `swiftc` not found. The crate builds its Swift shim (ArcBoxVZShim) with the \
         Xcode Command Line Tools, a documented prerequisite (CONTRIBUTING.md -> Prerequisites). \
         Install with `xcode-select --install`."
    );

    let config = if env::var("PROFILE").as_deref() == Ok("release") {
        "release"
    } else {
        "debug"
    };
    let triple = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64-apple-macosx13.0",
        Ok("x86_64") => "x86_64-apple-macosx13.0",
        other => panic!("arcbox-vz: unsupported macOS arch {other:?}"),
    };

    let pkg = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("shim");
    let scratch = PathBuf::from(env::var("OUT_DIR").unwrap()).join("swiftpm-scratch");

    // Shared by `build` and `--show-bin-path` so both resolve the same layout.
    let common = [
        "--package-path",
        pkg.to_str().unwrap(),
        "--scratch-path",
        scratch.to_str().unwrap(),
        "-c",
        config,
        "--triple",
        triple,
        "--product",
        "ArcBoxVZShim",
    ];

    let out = xcrun()
        .args(["swift", "build"])
        .args(common)
        .output()
        .expect("failed to spawn `xcrun swift build`");
    assert!(
        out.status.success(),
        "swift build failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let bin = xcrun()
        .args(["swift", "build"])
        .args(common)
        .arg("--show-bin-path")
        .output()
        .expect("failed to spawn `xcrun swift build --show-bin-path`");
    assert!(bin.status.success(), "swift build --show-bin-path failed");
    let bin_path = PathBuf::from(String::from_utf8(bin.stdout).unwrap().trim());
    assert!(
        bin_path.join("libArcBoxVZShim.a").exists(),
        "libArcBoxVZShim.a missing in {}",
        bin_path.display()
    );

    // The final link is driven by the environment's `cc` (the nix clang
    // wrapper inside the devenv shell), which resolves .tbd stubs against
    // ITS SDK. The Swift runtime search path must therefore come from the
    // same SDK the linker uses: honor SDKROOT when set, else the toolchain
    // default. Mixing 6.3-compiled Swift objects with another SDK's runtime
    // stubs is sound — the Swift ABI is stable and the dylibs resolve from
    // the dyld shared cache at runtime (no rpath needed).
    let swift_stub_dir = env::var("SDKROOT")
        .ok()
        .map(|s| format!("{s}/usr/lib/swift"))
        .filter(|p| PathBuf::from(p).is_dir())
        .unwrap_or_else(|| {
            let sdk = xcrun()
                .args(["--sdk", "macosx", "--show-sdk-path"])
                .output()
                .expect("failed to spawn `xcrun --show-sdk-path`");
            assert!(sdk.status.success(), "xcrun --show-sdk-path failed");
            format!(
                "{}/usr/lib/swift",
                String::from_utf8(sdk.stdout).unwrap().trim()
            )
        });

    println!("cargo:rustc-link-search=native={}", bin_path.display());
    println!("cargo:rustc-link-lib=static=ArcBoxVZShim");
    println!("cargo:rustc-link-search=native={swift_stub_dir}");
    // ld does not honor the archive's LC_LINKER_OPTION autolink hints when
    // rustc drives the link, so forward the Swift runtime libs explicitly.
    for lib in autolink_swift_libs(&bin_path.join("libArcBoxVZShim.a")) {
        println!("cargo:rustc-link-lib=dylib={lib}");
    }
    // Explicit rather than autolink: deterministic, and it replaces the old
    // runtime dlopen of Virtualization.framework.
    println!("cargo:rustc-link-lib=framework=Virtualization");
    println!("cargo:rustc-link-lib=framework=Foundation");
}

/// Swift runtime libraries the shim's objects autolink (`LC_LINKER_OPTION`).
///
/// Only `-lswift*` and `-lobjc` are forwarded: the SDK's `usr/lib/swift`
/// stubs resolve them. `swiftCompatibility*` shims are skipped — they are
/// static archives in the toolchain (not the SDK) backfilling runtimes older
/// than our macOS 13 deployment floor, so none of their symbols are
/// referenced.
fn autolink_swift_libs(archive: &std::path::Path) -> Vec<String> {
    let out = xcrun()
        .args(["otool", "-l"])
        .arg(archive)
        .output()
        .expect("failed to spawn `xcrun otool -l`");
    assert!(
        out.status.success(),
        "otool -l failed on {}",
        archive.display()
    );

    let mut libs: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let opt = line.trim().strip_prefix("string #")?.split_once(' ')?.1;
            let lib = opt.strip_prefix("-l")?;
            ((lib.starts_with("swift") && !lib.starts_with("swiftCompatibility")) || lib == "objc")
                .then(|| lib.to_string())
        })
        .collect();
    libs.sort();
    libs.dedup();
    assert!(
        libs.iter().any(|l| l == "swiftCore"),
        "no swiftCore autolink entry found in {} — otool parse broke?",
        archive.display()
    );
    libs
}
