//! The containerd configuration the agent writes at runtime.
//!
//! Lives outside `agent/linux/` for one concrete reason: everything in that
//! module is `#[cfg(target_os = "linux")]`, so its unit tests never compile on
//! a macOS dev host — and CI excludes this crate from build, test and clippy
//! entirely (`guest/AGENTS.md`). Rendering a config file is pure string work
//! with no Linux in it, so keeping it here is what makes the tests below
//! actually run somewhere.

use arcbox_constants::paths::{K3S_CNI_BIN_DIR, K3S_CNI_CONF_DIR};

/// Overlay mount options every container rootfs is mounted with.
///
/// `nfs_export=on` is what lets the in-kernel nfsd encode file handles for an
/// overlay mount, which is the precondition for browsing a *running*
/// container's filesystem through `~/ArcBox` (ABX-424). Committed layers are
/// already visible there; the merged view a live container sees is not, and
/// without this the kernel cannot name its inodes to a client.
///
/// `index=on` is spelled out rather than left to the kernel, because the
/// kernel's handling of the pair is three-way and only one branch is loud
/// (`ovl_fs_params_verify`, `fs/overlayfs/params.c`):
///
///  - **explicit `index=off` + explicit `nfs_export=on` → `EINVAL`.** This is
///    our case, and until arcboxlabs/boot-assets#52 it is what we got: the
///    stock overlay snapshotter appended `index=off` after whatever the config
///    asked for, so the kernel saw `index=on,nfs_export=on,index=off`,
///    last-wins, and refused every container's mount. The patched containerd
///    in boot bundle 0.8.6 is what makes this line take effect rather than
///    break the guest.
///  - **`index` left unset → the kernel turns it on itself** and the mount
///    succeeds. Harmless in isolation, but not a reason to trim `index=on`
///    from this list: containerd decides whether to append its own `index=off`
///    by looking at *these* options, so dropping it here puts us straight back
///    in the first branch.
///  - **no upper layer, with redirects followed → `nfs_export` is silently
///    turned off** with only a `pr_info`. That is the one branch that fails
///    quietly, and it is why a no-upper overlay would need
///    `redirect_dir=nofollow`.
///
/// That last option is absent because nothing here mounts a no-upper overlay:
/// containerd appends these options only on its overlay mount path, which it
/// reaches for active snapshots (always with an upperdir) and for
/// multi-parent views — and `image_snapshot_paths` reads a view's mount *spec*
/// and removes it without ever mounting. Add it if that changes.
///
/// The cost is one `trusted.overlay.origin` xattr per copy-up; in exchange
/// `index=on` stops copy-up from breaking hard links, which is a fix in its
/// own right. It also forbids reusing an upperdir across overlay mounts —
/// harmless here, since every snapshot owns its upper.
const OVERLAY_MOUNT_OPTIONS: &str = r#"["index=on", "nfs_export=on"]"#;

/// The config as authored, with `@NAME@` placeholders still in it.
///
/// Kept as a real `.toml` file so it reads as the thing it is: escaped quotes
/// and `\x20` indentation inside a Rust string literal were the sign that the
/// previous form was fighting the language rather than expressing it.
/// `include_str!` rather than a runtime read, so the config cannot lag the
/// agent that depends on it.
const CONTAINERD_CONFIG_TEMPLATE: &str = include_str!("containerd-config.toml");

pub fn render() -> String {
    CONTAINERD_CONFIG_TEMPLATE
        .replace("@CNI_BIN_DIR@", K3S_CNI_BIN_DIR)
        .replace("@CNI_CONF_DIR@", K3S_CNI_CONF_DIR)
        .replace("@OVERLAY_MOUNT_OPTIONS@", OVERLAY_MOUNT_OPTIONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cni_paths_come_from_the_shared_constants() {
        let config = render();
        assert!(config.contains(&format!("bin_dir = \"{K3S_CNI_BIN_DIR}\"")));
        assert!(config.contains(&format!("conf_dir = \"{K3S_CNI_CONF_DIR}\"")));
        assert!(config.contains("max_conf_num = 1"));
    }

    /// A template's own failure mode: a placeholder nobody substitutes.
    ///
    /// It is not always loud. `mount_options = @OVERLAY_MOUNT_OPTIONS@` is a
    /// parse error and would at least stop containerd, but
    /// `bin_dir = "@CNI_BIN_DIR@"` is perfectly valid TOML carrying a nonsense
    /// path — a silent misconfiguration. Nothing downstream would say so.
    ///
    /// Comments are exempt: the file documents its own placeholder convention,
    /// and prose about the `@NAME@` form is not a setting anyone reads. (This
    /// exemption is not hypothetical — the first run of this test failed on
    /// exactly that sentence.)
    #[test]
    fn no_placeholder_survives_rendering_outside_comments() {
        let config = render();
        let leftovers: Vec<&str> = config
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .filter(|line| line.contains('@'))
            .collect();
        assert!(
            leftovers.is_empty(),
            "unsubstituted placeholder left in the rendered config: {leftovers:?}"
        );
    }

    /// containerd refuses to start on a malformed config, and it does so during
    /// guest bring-up where the symptom is a readiness timeout rather than a
    /// parse error. Parsing here is cheap; reading the boot log to find a stray
    /// quote is not.
    #[test]
    fn the_rendered_config_is_valid_toml() {
        let parsed: toml::Value = render().parse().expect("config must be valid TOML");
        assert_eq!(parsed["version"].as_integer(), Some(2));
    }

    /// The two options travel together by kernel rule, not by preference:
    /// explicit `index=off` alongside `nfs_export=on` is rejected outright on a
    /// read-write mount, and a container rootfs is one.
    #[test]
    fn overlay_mount_options_keep_nfs_export_and_index_together() {
        let parsed: toml::Value = render().parse().unwrap();
        let options = parsed["plugins"]["io.containerd.snapshotter.v1.overlayfs"]["mount_options"]
            .as_array()
            .expect("overlayfs snapshotter must declare mount_options")
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();

        assert!(options.contains(&"nfs_export=on".to_owned()));
        assert!(
            options.contains(&"index=on".to_owned()),
            "nfs_export=on without index=on is rejected by the kernel: {options:?}"
        );
        assert!(
            !options.iter().any(|option| option == "index=off"),
            "index=off would conflict with nfs_export=on: {options:?}"
        );
    }
}
