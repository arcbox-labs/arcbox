//! Custom Finder icon for the `~/ArcBox` network volume.
//!
//! When a user assigns an icon to a network volume, macOS drops two files
//! at the volume root: `.VolumeIcon.icns` (the icon) and `._.` (an
//! AppleDouble sidecar whose Finder info carries the custom-icon flag for
//! the root directory). The export is read-only for the host, so the
//! guest places the same two files server-side and every client renders
//! the ArcBox icon.

use std::path::Path;

/// Icon bytes served as `.VolumeIcon.icns` at the export root.
const VOLUME_ICON: &[u8] = include_bytes!("../assets/VolumeIcon.icns");

/// `kHasCustomIcon` in Finder flags.
const K_HAS_CUSTOM_ICON: u16 = 0x0400;

/// Writes `.VolumeIcon.icns` + `._.` into `root` (idempotent).
///
/// Best-effort by contract: callers log a warning on `Err` — a missing
/// icon must never break the export.
pub fn install(root: &Path) -> Result<(), String> {
    write_if_changed(&root.join(".VolumeIcon.icns"), VOLUME_ICON)?;
    write_if_changed(
        &root.join("._."),
        &apple_double_finder_info(K_HAS_CUSTOM_ICON),
    )
}

fn write_if_changed(path: &Path, contents: &[u8]) -> Result<(), String> {
    if std::fs::read(path).is_ok_and(|existing| existing == contents) {
        return Ok(());
    }
    std::fs::write(path, contents).map_err(|e| format!("write {} failed({e})", path.display()))
}

/// Builds a minimal AppleDouble file carrying only a Finder Info entry
/// with `finder_flags` set (directory layout: `frFlags` at bytes 8..10).
///
/// Layout per the AppleSingle/AppleDouble format spec: magic, version 2,
/// 16 filler bytes, entry count, then one entry descriptor
/// (id 9 = Finder Info, offset 38, length 32) and the 32-byte payload.
fn apple_double_finder_info(finder_flags: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(70);
    out.extend_from_slice(&0x0005_1607_u32.to_be_bytes()); // AppleDouble magic
    out.extend_from_slice(&0x0002_0000_u32.to_be_bytes()); // version 2
    out.extend_from_slice(&[0u8; 16]); // filler
    out.extend_from_slice(&1_u16.to_be_bytes()); // one entry
    out.extend_from_slice(&9_u32.to_be_bytes()); // entry id: Finder Info
    out.extend_from_slice(&38_u32.to_be_bytes()); // payload offset
    out.extend_from_slice(&32_u32.to_be_bytes()); // payload length
    let mut finder_info = [0u8; 32];
    finder_info[8..10].copy_from_slice(&finder_flags.to_be_bytes());
    out.extend_from_slice(&finder_info);
    out
}

#[cfg(test)]
mod tests {
    use super::{K_HAS_CUSTOM_ICON, VOLUME_ICON, apple_double_finder_info, install};

    #[test]
    fn apple_double_layout_is_exact() {
        let blob = apple_double_finder_info(K_HAS_CUSTOM_ICON);
        assert_eq!(blob.len(), 70);
        assert_eq!(&blob[0..4], &[0x00, 0x05, 0x16, 0x07]);
        assert_eq!(&blob[4..8], &[0x00, 0x02, 0x00, 0x00]);
        assert_eq!(&blob[24..26], &[0x00, 0x01]); // entry count
        assert_eq!(&blob[26..30], &[0x00, 0x00, 0x00, 0x09]); // Finder Info id
        assert_eq!(&blob[30..34], &[0x00, 0x00, 0x00, 38]); // offset
        assert_eq!(&blob[34..38], &[0x00, 0x00, 0x00, 32]); // length
        // frFlags carries kHasCustomIcon; everything else stays zero.
        assert_eq!(&blob[38 + 8..38 + 10], &[0x04, 0x00]);
        assert!(blob[38..46].iter().all(|&b| b == 0));
        assert!(blob[48..].iter().all(|&b| b == 0));
    }

    #[test]
    fn embedded_icon_is_an_icns() {
        assert_eq!(&VOLUME_ICON[0..4], b"icns");
    }

    #[test]
    fn install_writes_both_files_idempotently() {
        let dir = tempfile::tempdir().expect("tempdir");
        install(dir.path()).expect("first install");
        let icon = dir.path().join(".VolumeIcon.icns");
        let sidecar = dir.path().join("._.");
        assert_eq!(std::fs::read(&icon).expect("icon"), VOLUME_ICON);
        assert_eq!(
            std::fs::read(&sidecar).expect("sidecar"),
            apple_double_finder_info(K_HAS_CUSTOM_ICON)
        );
        // Second pass rewrites nothing (mtime unchanged proves the skip).
        let mtime = std::fs::metadata(&icon)
            .expect("meta")
            .modified()
            .expect("mtime");
        install(dir.path()).expect("second install");
        assert_eq!(
            std::fs::metadata(&icon)
                .expect("meta")
                .modified()
                .expect("mtime"),
            mtime
        );
    }
}
