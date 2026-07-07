use std::path::PathBuf;

pub mod boot_assets;
pub mod daemon;
pub mod signing;

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("tests/e2e lives two levels below the repository root")
        .to_owned()
}
