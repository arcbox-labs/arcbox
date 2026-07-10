use anyhow::Result;
use xtask_kit::{fs as xtask_fs, hash::sha256_file};

use crate::FleetAssetArgs;

/// Stage one `arcbox-fleet-agent` binary as a raw release asset plus its
/// `.sha256` file. The fleet agent ships as a bare binary, not an archive:
/// the release tag carries the version, so the asset name is a pure function
/// of the platform slug, and the checksum covers exactly the bytes the
/// updater executes. File modes are irrelevant here — HTTP carries none, so
/// installers and the self-updater chmod after download.
pub fn run(args: FleetAssetArgs) -> Result<()> {
    xtask_fs::create_dir_all(&args.output_dir)?;

    let asset_name = format!("arcbox-fleet-agent-{}", args.platform);
    let asset = args.output_dir.join(&asset_name);
    xtask_fs::copy_file(&args.binary, &asset)?;

    let digest = sha256_file(&asset)?;
    let checksum = args.output_dir.join(format!("{asset_name}.sha256"));
    xtask_fs::write_string(&checksum, format!("{digest}  {asset_name}\n"))?;

    println!("{}", asset.display());
    println!("{}", checksum.display());

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    /// The `<hash>  <name>` two-space layout is a contract: it must remain
    /// verifiable with `shasum -a 256 -c` next to the downloaded asset.
    #[test]
    fn writes_versionless_asset_and_checkable_sha256() {
        let dir = tempfile::tempdir().expect("tempdir");
        let binary = dir.path().join("arcbox-fleet-agent");
        fs::write(&binary, b"binary bytes").expect("write dummy binary");

        let output_dir = dir.path().join("out");
        run(FleetAssetArgs {
            platform: "linux-amd64".to_owned(),
            binary: binary.clone(),
            output_dir: output_dir.clone(),
        })
        .expect("staging succeeds");

        let asset = output_dir.join("arcbox-fleet-agent-linux-amd64");
        assert_eq!(
            fs::read(&asset).expect("asset exists"),
            fs::read(&binary).expect("input exists"),
        );

        let checksum = fs::read_to_string(output_dir.join("arcbox-fleet-agent-linux-amd64.sha256"))
            .expect("checksum exists");
        let expected = sha256_file(&asset).expect("hash asset");
        assert_eq!(
            checksum,
            format!("{expected}  arcbox-fleet-agent-linux-amd64\n")
        );
    }
}
